"""Formato de la bóveda, cifrado AES-256-GCM y escritura atómica.

Estructura del archivo JSON (versión 1):

    {
      "formato": "gestor-contrasenas-educativo",
      "version": 1,
      "kdf": {"nombre": "argon2id", "sal": "<b64>", "tiempo": 3, ...},
      "cifrado": {"algoritmo": "AES-256-GCM", "nonce": "<b64 12 bytes>"},
      "metadatos": {"creada": "...", "modificada": "..."},
      "texto_cifrado": "<b64: cifrado + etiqueta de 16 bytes>"
    }

Todo lo que no es `texto_cifrado` es la CABECERA. La cabecera va en claro
(hace falta para derivar la clave), pero se pasa a AES-GCM como datos
asociados (AAD): si alguien cambia un solo byte de la cabecera, la etiqueta
de autenticación deja de coincidir y el descifrado falla con InvalidTag.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gestor import kdf
from gestor.codificacion import ErrorCodificacion, a_b64, de_b64

FORMATO = "gestor-contrasenas-educativo"
VERSION = 1
ALGORITMO = "AES-256-GCM"
LONGITUD_NONCE = 12  # 96 bits: el tamaño recomendado para GCM (NIST SP 800-38D)
CAMPOS_ENTRADA = ("usuario", "contrasena", "url", "notas")

MENSAJE_AUTENTICACION = (
    "No se pudo abrir la bóveda: la contraseña maestra es incorrecta "
    "o el archivo ha sido modificado."
)


class ErrorBoveda(Exception):
    """Error genérico de la bóveda (formato, archivo, entradas...)."""


class ErrorAutenticacion(ErrorBoveda):
    """Maestra incorrecta o bóveda manipulada.

    A propósito NO distinguimos entre ambos casos: AES-GCM tampoco puede, y
    dar pistas distintas ayudaría a un atacante.
    """

    def __init__(self, mensaje: str = MENSAJE_AUTENTICACION):
        super().__init__(mensaje)


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Cifrado / descifrado de bajo nivel
# ---------------------------------------------------------------------------

def aad_de_cabecera(cabecera: dict) -> bytes:
    """Serialización CANÓNICA de la cabecera para usarla como AAD.

    `sort_keys` y separadores fijos garantizan que los mismos datos producen
    siempre los mismos bytes, aunque el JSON del disco tenga otro orden o
    espaciado.
    """
    return json.dumps(
        cabecera, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def cifrar_documento(clave: bytes, kdf_parametros: dict, metadatos: dict, datos: dict) -> dict:
    """Cifra `datos` y devuelve el documento completo listo para guardar."""
    # Nonce NUEVO en cada cifrado. Con la misma clave, repetir un nonce en GCM
    # revela el XOR de los textos en claro y permite falsificar mensajes.
    nonce = secrets.token_bytes(LONGITUD_NONCE)
    cabecera = {
        "formato": FORMATO,
        "version": VERSION,
        "kdf": kdf_parametros,
        "cifrado": {"algoritmo": ALGORITMO, "nonce": a_b64(nonce)},
        "metadatos": metadatos,
    }
    texto_claro = json.dumps(datos, ensure_ascii=False, sort_keys=True).encode("utf-8")
    texto_cifrado = AESGCM(clave).encrypt(nonce, texto_claro, aad_de_cabecera(cabecera))
    return {**cabecera, "texto_cifrado": a_b64(texto_cifrado)}


def separar_cabecera(documento: dict) -> tuple[dict, bytes, bytes]:
    """Valida la estructura y devuelve (cabecera, nonce, texto_cifrado)."""
    if not isinstance(documento, dict):
        raise ErrorBoveda("la bóveda no es un objeto JSON")
    esperados = {"formato", "version", "kdf", "cifrado", "metadatos", "texto_cifrado"}
    if set(documento) != esperados:
        raise ErrorBoveda("la bóveda tiene campos ausentes o inesperados")
    if documento["formato"] != FORMATO:
        raise ErrorBoveda("el archivo no es una bóveda de este programa")
    if documento["version"] != VERSION:
        raise ErrorBoveda(f"versión de bóveda no soportada: {documento['version']!r}")
    cifrado = documento["cifrado"]
    if not isinstance(cifrado, dict) or cifrado.get("algoritmo") != ALGORITMO or set(cifrado) != {"algoritmo", "nonce"}:
        raise ErrorBoveda("algoritmo de cifrado no soportado")
    if not isinstance(documento["metadatos"], dict):
        raise ErrorBoveda("metadatos inválidos")
    try:
        kdf.validar_parametros(documento["kdf"])
        nonce = de_b64(cifrado["nonce"])
        texto_cifrado = de_b64(documento["texto_cifrado"])
    except (kdf.ErrorKDF, ErrorCodificacion) as exc:
        raise ErrorBoveda(f"bóveda corrupta: {exc}") from exc
    if len(nonce) != LONGITUD_NONCE:
        raise ErrorBoveda("nonce de longitud incorrecta")
    if len(texto_cifrado) < 16:  # al menos la etiqueta GCM
        raise ErrorBoveda("texto cifrado demasiado corto")
    cabecera = {k: v for k, v in documento.items() if k != "texto_cifrado"}
    return cabecera, nonce, texto_cifrado


def descifrar_documento(clave: bytes, documento: dict) -> dict:
    """Descifra y autentica. Lanza ErrorAutenticacion si algo no cuadra."""
    cabecera, nonce, texto_cifrado = separar_cabecera(documento)
    try:
        texto_claro = AESGCM(clave).decrypt(nonce, texto_cifrado, aad_de_cabecera(cabecera))
    except InvalidTag:
        # `from None`: no encadenamos la excepción original; no aporta nada
        # útil y así el mensaje es siempre el mismo.
        raise ErrorAutenticacion() from None
    datos = json.loads(texto_claro.decode("utf-8"))
    if not isinstance(datos, dict) or not isinstance(datos.get("entradas"), dict):
        raise ErrorBoveda("contenido descifrado con formato inesperado")
    return datos


# ---------------------------------------------------------------------------
# Archivo
# ---------------------------------------------------------------------------

def escribir_atomico(ruta: Path, contenido: bytes) -> None:
    """Escribe sin riesgo de dejar el archivo a medias.

    1. Se crea un temporal en el MISMO directorio (os.replace solo es atómico
       dentro del mismo sistema de archivos). mkstemp ya lo crea con 0600.
    2. Se escribe, se hace flush y fsync (los datos llegan al disco).
    3. os.replace sustituye el archivo de golpe: quien lo lea verá la versión
       vieja completa o la nueva completa, nunca una mezcla.
    4. fsync del directorio para que el cambio de nombre también persista.
    """
    ruta = Path(ruta)
    directorio = ruta.parent if str(ruta.parent) else Path(".")
    directorio.mkdir(parents=True, exist_ok=True)
    fd, temporal = tempfile.mkstemp(prefix=f".{ruta.name}.", suffix=".tmp", dir=directorio)
    try:
        with os.fdopen(fd, "wb") as f:
            if hasattr(os, "fchmod"):
                os.fchmod(f.fileno(), 0o600)
            f.write(contenido)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporal, ruta)
    except BaseException:
        try:
            os.unlink(temporal)
        except FileNotFoundError:
            pass
        raise
    try:
        os.chmod(ruta, 0o600)
    except OSError:
        pass
    if hasattr(os, "O_DIRECTORY"):
        dfd = os.open(directorio, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def leer_documento(ruta: Path) -> dict:
    try:
        texto = Path(ruta).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ErrorBoveda(f"no existe la bóveda {ruta}. Créala con `init`.") from None
    try:
        return json.loads(texto)
    except json.JSONDecodeError as exc:
        raise ErrorBoveda(f"la bóveda no es JSON válido: {exc}") from None


# ---------------------------------------------------------------------------
# API de alto nivel
# ---------------------------------------------------------------------------

class Boveda:
    """Bóveda abierta en memoria.

    La clave derivada vive en este objeto mientras está abierta. Python no
    permite borrar de forma fiable un secreto de la memoria (los `bytes` son
    inmutables y el recolector puede copiarlos), limitación documentada en
    CRIPTOGRAFIA.md.
    """

    def __init__(self, ruta: Path, clave: bytes, kdf_parametros: dict, metadatos: dict, entradas: dict):
        self.ruta = Path(ruta)
        self._clave = clave
        self.kdf_parametros = kdf_parametros
        self.metadatos = metadatos
        self.entradas = entradas

    # -- ciclo de vida -------------------------------------------------------

    @classmethod
    def crear(cls, ruta: Path, maestra: str, kdf_parametros: dict | None = None, sobrescribir: bool = False) -> "Boveda":
        ruta = Path(ruta)
        if ruta.exists() and not sobrescribir:
            raise ErrorBoveda(f"ya existe una bóveda en {ruta}")
        # Sal nueva por bóveda: dos bóvedas con la misma maestra tienen
        # claves distintas y no se pueden atacar a la vez.
        parametros = dict(kdf_parametros) if kdf_parametros else kdf.nuevos_parametros()
        clave = kdf.derivar_clave(maestra, parametros)
        ahora = _ahora()
        boveda = cls(ruta, clave, parametros, {"creada": ahora, "modificada": ahora}, {})
        boveda.guardar()
        return boveda

    @classmethod
    def abrir(cls, ruta: Path, maestra: str) -> "Boveda":
        documento = leer_documento(ruta)
        separar_cabecera(documento)  # valida antes de gastar tiempo en el KDF
        clave = kdf.derivar_clave(maestra, documento["kdf"])
        datos = descifrar_documento(clave, documento)
        return cls(ruta, clave, documento["kdf"], documento["metadatos"], datos["entradas"])

    def guardar(self) -> dict:
        self.metadatos = {**self.metadatos, "modificada": _ahora()}
        documento = cifrar_documento(self._clave, self.kdf_parametros, self.metadatos, {"entradas": self.entradas})
        contenido = json.dumps(documento, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
        escribir_atomico(self.ruta, contenido)
        return documento

    def cambiar_maestra(self, nueva: str, kdf_parametros: dict | None = None) -> None:
        """Re-cifra todo con una clave nueva (sal nueva incluida)."""
        if kdf_parametros is None:
            ajustes = {k: v for k, v in self.kdf_parametros.items() if k not in ("nombre", "sal")}
            kdf_parametros = kdf.nuevos_parametros(self.kdf_parametros["nombre"], **ajustes)
        else:
            kdf_parametros = dict(kdf_parametros)
            kdf_parametros["sal"] = a_b64(secrets.token_bytes(kdf.LONGITUD_SAL))
        self._clave = kdf.derivar_clave(nueva, kdf_parametros)
        self.kdf_parametros = kdf_parametros
        self.guardar()

    # -- entradas ------------------------------------------------------------

    def agregar(self, nombre: str, contrasena: str, usuario: str = "", url: str = "", notas: str = "", reemplazar: bool = False) -> None:
        nombre = nombre.strip()
        if not nombre:
            raise ErrorBoveda("el nombre de la entrada no puede estar vacío")
        if not contrasena:
            raise ErrorBoveda("la contraseña no puede estar vacía")
        existente = self.entradas.get(nombre)
        if existente and not reemplazar:
            raise ErrorBoveda(f"ya existe la entrada {nombre!r} (usa --reemplazar)")
        ahora = _ahora()
        self.entradas[nombre] = {
            "usuario": usuario,
            "contrasena": contrasena,
            "url": url,
            "notas": notas,
            "creada": existente["creada"] if existente else ahora,
            "modificada": ahora,
        }
        self.guardar()

    def obtener(self, nombre: str) -> dict:
        try:
            return self.entradas[nombre]
        except KeyError:
            raise ErrorBoveda(f"no existe la entrada {nombre!r}") from None

    def eliminar(self, nombre: str) -> None:
        self.obtener(nombre)
        del self.entradas[nombre]
        self.guardar()

    def listar(self) -> list[tuple[str, dict]]:
        return sorted(self.entradas.items(), key=lambda par: par[0].casefold())
