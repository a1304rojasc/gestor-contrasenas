import pytest

from gestor import kdf


def test_clave_de_32_bytes_y_determinista(params_kdf):
    c1 = kdf.derivar_clave("maestra", params_kdf)
    assert len(c1) == 32
    assert c1 == kdf.derivar_clave("maestra", params_kdf)
    assert c1 != kdf.derivar_clave("maestrA", params_kdf)


def test_predeterminados_seguros():
    a = kdf.nuevos_parametros(kdf.ARGON2ID)
    assert a["memoria_kib"] >= 19 * 1024 and a["tiempo"] >= 2
    assert kdf.nuevos_parametros(kdf.PBKDF2)["iteraciones"] >= 600_000
    assert kdf.avisos_parametros(a) == []


def test_parametros_bajos_generan_aviso(params_kdf):
    assert kdf.avisos_parametros(params_kdf)


def test_maestra_vacia_rechazada(params_kdf):
    with pytest.raises(kdf.ErrorKDF):
        kdf.derivar_clave("", params_kdf)


@pytest.mark.parametrize("cambio", [{"nombre": "sha1"}, {"sal": "AAAA"}, {"extra": 1}])
def test_parametros_invalidos(params_kdf, cambio):
    with pytest.raises(kdf.ErrorKDF):
        kdf.validar_parametros({**params_kdf, **cambio})
