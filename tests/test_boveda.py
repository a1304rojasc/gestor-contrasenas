import json
import os
import stat

import pytest

from gestor import kdf
from gestor.boveda import (
    Boveda,
    ErrorAutenticacion,
    ErrorBoveda,
    LONGITUD_NONCE,
    MENSAJE_AUTENTICACION,
    cifrar_documento,
    descifrar_documento,
)
from gestor.codificacion import a_b64, de_b64

MAESTRA = "correcta-caballo-bateria-grapa"


def _leer(ruta):
    return json.loads(ruta.read_text(encoding="utf-8"))


def _escribir(ruta, doc):
    ruta.write_text(json.dumps(doc), encoding="utf-8")


def _cambiar_un_byte_b64(texto, posicion=0):
    datos = bytearray(de_b64(texto))
    datos[posicion] ^= 0x01
    return a_b64(bytes(datos))


# -- ida y vuelta -------------------------------------------------------------

def test_ida_y_vuelta(ruta, params_kdf):
    b = Boveda.crear(ruta, MAESTRA, params_kdf)
    b.agregar("correo", "s3cr3to-ñandú-🔑", usuario="ana@ejemplo.org", url="https://correo.ejemplo")
    abierta = Boveda.abrir(ruta, MAESTRA)
    e = abierta.obtener("correo")
    assert e["contrasena"] == "s3cr3to-ñandú-🔑"
    assert e["usuario"] == "ana@ejemplo.org"


def test_texto_en_claro_no_aparece_en_disco(ruta, params_kdf):
    b = Boveda.crear(ruta, MAESTRA, params_kdf)
    b.agregar("banco", "NoDeberiaVerse123", usuario="usuario_visible")
    contenido = ruta.read_bytes()
    assert b"NoDeberiaVerse123" not in contenido
    assert b"usuario_visible" not in contenido
    assert b"banco" not in contenido


def test_cifrado_bajo_nivel_ida_y_vuelta():
    clave = os.urandom(32)
    p = kdf.nuevos_parametros(kdf.PBKDF2, iteraciones=1000)
    doc = cifrar_documento(clave, p, {}, {"entradas": {"x": {"contrasena": "y"}}})
    assert descifrar_documento(clave, doc)["entradas"]["x"]["contrasena"] == "y"


def test_normalizacion_unicode(ruta, params_kdf):
    # "ñ" precompuesta (NFC) frente a "n" + tilde combinada (NFD).
    Boveda.crear(ruta, "contraseña-larga", params_kdf)
    Boveda.abrir(ruta, "contraseña-larga")


# -- autenticación ---------------------------------------------------------------

def test_maestra_incorrecta_falla(ruta, params_kdf):
    Boveda.crear(ruta, MAESTRA, params_kdf).agregar("a", "b")
    with pytest.raises(ErrorAutenticacion) as info:
        Boveda.abrir(ruta, MAESTRA + "x")
    # Mensaje fijo: no distingue "maestra mala" de "archivo manipulado" ni
    # filtra datos; tampoco encadena la excepción InvalidTag original.
    assert str(info.value) == MENSAJE_AUTENTICACION
    assert info.value.__cause__ is None


@pytest.mark.parametrize("posicion", [0, 5, -1, -16])
def test_byte_cambiado_en_texto_cifrado_falla(ruta, params_kdf, posicion):
    Boveda.crear(ruta, MAESTRA, params_kdf).agregar("a", "b")
    doc = _leer(ruta)
    doc["texto_cifrado"] = _cambiar_un_byte_b64(doc["texto_cifrado"], posicion)
    _escribir(ruta, doc)
    with pytest.raises(ErrorAutenticacion):
        Boveda.abrir(ruta, MAESTRA)


def test_byte_cambiado_en_nonce_falla(ruta, params_kdf):
    Boveda.crear(ruta, MAESTRA, params_kdf)
    doc = _leer(ruta)
    doc["cifrado"]["nonce"] = _cambiar_un_byte_b64(doc["cifrado"]["nonce"])
    _escribir(ruta, doc)
    with pytest.raises(ErrorAutenticacion):
        Boveda.abrir(ruta, MAESTRA)


def test_cabecera_manipulada_metadatos_falla(ruta, params_kdf):
    """Los metadatos no influyen en la clave: SOLO el AAD detecta el cambio."""
    Boveda.crear(ruta, MAESTRA, params_kdf)
    doc = _leer(ruta)
    original = doc["metadatos"]["creada"]
    doc["metadatos"]["creada"] = original[:-1] + ("1" if original[-1] != "1" else "2")
    _escribir(ruta, doc)
    with pytest.raises(ErrorAutenticacion):
        Boveda.abrir(ruta, MAESTRA)


def test_cabecera_manipulada_sal_falla(ruta, params_kdf):
    Boveda.crear(ruta, MAESTRA, params_kdf)
    doc = _leer(ruta)
    doc["kdf"]["sal"] = _cambiar_un_byte_b64(doc["kdf"]["sal"])
    _escribir(ruta, doc)
    with pytest.raises(ErrorAutenticacion):
        Boveda.abrir(ruta, MAESTRA)


def test_cabecera_manipulada_parametro_kdf_falla(ruta, params_kdf):
    Boveda.crear(ruta, MAESTRA, params_kdf)
    doc = _leer(ruta)
    campo = "tiempo" if doc["kdf"]["nombre"] == kdf.ARGON2ID else "iteraciones"
    doc["kdf"][campo] += 1
    _escribir(ruta, doc)
    with pytest.raises(ErrorAutenticacion):
        Boveda.abrir(ruta, MAESTRA)


def test_aad_detecta_cambio_aunque_la_clave_sea_correcta():
    clave = os.urandom(32)
    p = kdf.nuevos_parametros(kdf.PBKDF2, iteraciones=1000)
    doc = cifrar_documento(clave, p, {"nota": "a"}, {"entradas": {}})
    doc["metadatos"]["nota"] = "b"
    with pytest.raises(ErrorAutenticacion):
        descifrar_documento(clave, doc)


@pytest.mark.parametrize(
    "cambio",
    [
        lambda d: d.update(version=2),
        lambda d: d.update(formato="otro"),
        lambda d: d["cifrado"].update(algoritmo="AES-128-CBC"),
        lambda d: d.update(extra=1),
        lambda d: d.pop("metadatos"),
        lambda d: d.update(texto_cifrado="no*es*base64"),
        lambda d: d["kdf"].update(nombre="md5"),
    ],
)
def test_cabecera_invalida_da_error_claro(ruta, params_kdf, cambio):
    Boveda.crear(ruta, MAESTRA, params_kdf)
    doc = _leer(ruta)
    cambio(doc)
    _escribir(ruta, doc)
    with pytest.raises(ErrorBoveda):
        Boveda.abrir(ruta, MAESTRA)


def test_parametros_kdf_desorbitados_se_rechazan(ruta, params_kdf):
    """Un archivo malicioso no puede pedir 1 TiB de RAM (denegación de servicio)."""
    Boveda.crear(ruta, MAESTRA, params_kdf)
    doc = _leer(ruta)
    campo = "memoria_kib" if doc["kdf"]["nombre"] == kdf.ARGON2ID else "iteraciones"
    doc["kdf"][campo] = 10**12
    _escribir(ruta, doc)
    with pytest.raises(ErrorBoveda, match="máximo"):
        Boveda.abrir(ruta, MAESTRA)


# -- nonces y sales -------------------------------------------------------------

def test_nonces_nunca_se_repiten(ruta, params_kdf):
    b = Boveda.crear(ruta, MAESTRA, params_kdf)
    nonces = {de_b64(b.guardar()["cifrado"]["nonce"]) for _ in range(300)}
    assert len(nonces) == 300
    assert all(len(n) == LONGITUD_NONCE for n in nonces)


def test_mismo_contenido_da_cifrados_distintos(ruta, params_kdf):
    b = Boveda.crear(ruta, MAESTRA, params_kdf)
    assert b.guardar()["texto_cifrado"] != b.guardar()["texto_cifrado"]


def test_sal_distinta_por_boveda(tmp_path, params_kdf):
    nombre = params_kdf["nombre"]
    ajustes = {k: v for k, v in params_kdf.items() if k not in ("nombre", "sal")}
    sales, claves = set(), set()
    for i in range(10):
        b = Boveda.crear(tmp_path / f"b{i}.json", MAESTRA, kdf.nuevos_parametros(nombre, **ajustes))
        sales.add(b.kdf_parametros["sal"])
        claves.add(b._clave)
        assert len(de_b64(b.kdf_parametros["sal"])) == kdf.LONGITUD_SAL
    assert len(sales) == 10
    assert len(claves) == 10  # misma maestra, claves distintas


# -- archivo -------------------------------------------------------------------

@pytest.mark.skipif(os.name != "posix", reason="permisos POSIX")
def test_permisos_0600(ruta, params_kdf):
    b = Boveda.crear(ruta, MAESTRA, params_kdf)
    b.agregar("a", "b")
    assert stat.S_IMODE(ruta.stat().st_mode) == 0o600


def test_escritura_atomica_no_deja_temporales(ruta, params_kdf):
    b = Boveda.crear(ruta, MAESTRA, params_kdf)
    for i in range(5):
        b.agregar(f"e{i}", "x")
    assert sorted(p.name for p in ruta.parent.iterdir()) == [ruta.name]


def test_fallo_al_escribir_conserva_la_version_anterior(ruta, params_kdf, monkeypatch):
    b = Boveda.crear(ruta, MAESTRA, params_kdf)
    b.agregar("a", "1")
    antes = ruta.read_bytes()

    def falla(*_a, **_k):
        raise OSError("disco lleno (simulado)")

    monkeypatch.setattr("gestor.boveda.os.replace", falla)
    with pytest.raises(OSError):
        b.agregar("b", "2")
    assert ruta.read_bytes() == antes
    assert sorted(p.name for p in ruta.parent.iterdir()) == [ruta.name]


def test_no_sobrescribe_sin_permiso(ruta, params_kdf):
    Boveda.crear(ruta, MAESTRA, params_kdf)
    with pytest.raises(ErrorBoveda):
        Boveda.crear(ruta, MAESTRA, params_kdf)


# -- entradas y cambio de maestra ------------------------------------------------

def test_agregar_eliminar_listar(ruta, params_kdf):
    b = Boveda.crear(ruta, MAESTRA, params_kdf)
    b.agregar("zeta", "1")
    b.agregar("Alfa", "2")
    with pytest.raises(ErrorBoveda):
        b.agregar("zeta", "3")
    b.agregar("zeta", "3", reemplazar=True)
    assert [n for n, _ in b.listar()] == ["Alfa", "zeta"]
    b.eliminar("Alfa")
    abierta = Boveda.abrir(ruta, MAESTRA)
    assert list(abierta.entradas) == ["zeta"]
    assert abierta.obtener("zeta")["contrasena"] == "3"
    with pytest.raises(ErrorBoveda):
        abierta.obtener("Alfa")


def test_cambiar_maestra_conserva_entradas(ruta, params_kdf):
    b = Boveda.crear(ruta, MAESTRA, params_kdf)
    for i in range(5):
        b.agregar(f"sitio{i}", f"clave{i}", usuario=f"u{i}")
    sal_vieja = b.kdf_parametros["sal"]
    b.cambiar_maestra("otra-maestra-nueva-y-larga")
    assert b.kdf_parametros["sal"] != sal_vieja
    with pytest.raises(ErrorAutenticacion):
        Boveda.abrir(ruta, MAESTRA)
    abierta = Boveda.abrir(ruta, "otra-maestra-nueva-y-larga")
    assert {n: e["contrasena"] for n, e in abierta.listar()} == {f"sitio{i}": f"clave{i}" for i in range(5)}


def test_cambiar_maestra_y_kdf(ruta, ajustes_kdf):
    b = Boveda.crear(ruta, MAESTRA, kdf.nuevos_parametros(kdf.PBKDF2, **ajustes_kdf[kdf.PBKDF2]))
    b.agregar("a", "b")
    b.cambiar_maestra("nueva-maestra", kdf.nuevos_parametros(kdf.ARGON2ID, **ajustes_kdf[kdf.ARGON2ID]))
    abierta = Boveda.abrir(ruta, "nueva-maestra")
    assert abierta.kdf_parametros["nombre"] == kdf.ARGON2ID
    assert abierta.obtener("a")["contrasena"] == "b"
