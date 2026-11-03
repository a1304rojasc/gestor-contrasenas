"""Derivación de la clave de cifrado a partir de la contraseña maestra.

Una contraseña humana NO es una clave criptográfica: tiene poca entropía y no
mide 32 bytes. Un KDF (Key Derivation Function) la transforma en una clave de
256 bits y, sobre todo, hace que cada intento de adivinarla sea CARO.

- Argon2id (predeterminado): lento y "duro en memoria" (memory-hard). Obliga
  a un atacante con GPU/ASIC a gastar mucha RAM por intento.
- PBKDF2-HMAC-SHA256 (alternativa): solo es lento en CPU; se paraleliza bien
  en GPU, por eso necesita muchísimas iteraciones (OWASP 2023: ≥600 000).

Los parámetros (incluida la sal) se guardan en la cabecera de la bóveda. No
son secretos: sirven para poder volver a derivar la misma clave y para poder
endurecerlos en el futuro (`cambiar-maestra --kdf ...`).
"""

from __future__ import annotations

import hashlib
import secrets
import unicodedata

from argon2.low_level import Type, hash_secret_raw

from gestor.codificacion import ErrorCodificacion, a_b64, de_b64

LONGITUD_CLAVE = 32  # 256 bits -> AES-256
LONGITUD_SAL = 16  # 128 bits, suficiente para que nunca se repita

ARGON2ID = "argon2id"
PBKDF2 = "pbkdf2-sha256"

# RFC 9106, segunda opción recomendada: t=3, m=64 MiB, p=4.
PREDETERMINADOS: dict[str, dict] = {
    ARGON2ID: {"tiempo": 3, "memoria_kib": 64 * 1024, "paralelismo": 4},
    PBKDF2: {"iteraciones": 600_000},
}

# Mínimos recomendados: por debajo avisamos (los tests usan valores bajos a
# propósito para ser rápidos, por eso es un aviso y no un error).
MINIMOS_RECOMENDADOS: dict[str, dict] = {
    ARGON2ID: {"tiempo": 2, "memoria_kib": 19 * 1024, "paralelismo": 1},
    PBKDF2: {"iteraciones": 600_000},
}

# Máximos: un archivo manipulado podría pedir 1 TiB de RAM o 10^12
# iteraciones para colgar el programa (denegación de servicio).
MAXIMOS: dict[str, dict] = {
    ARGON2ID: {"tiempo": 50, "memoria_kib": 4 * 1024 * 1024, "paralelismo": 64},
    PBKDF2: {"iteraciones": 50_000_000},
}


class ErrorKDF(ValueError):
    """Parámetros de KDF inválidos."""


def normalizar_maestra(maestra: str) -> bytes:
    """Convierte la contraseña a bytes de forma estable.

    "ñ" puede escribirse como un solo carácter (U+00F1) o como "n" + tilde
    combinada (U+006E U+0303). Se ven iguales pero son bytes distintos y
    darían claves distintas. NFC unifica ambas formas.
    """
    if not isinstance(maestra, str) or maestra == "":
        raise ErrorKDF("la contraseña maestra no puede estar vacía")
    return unicodedata.normalize("NFC", maestra).encode("utf-8")


def nuevos_parametros(nombre: str = ARGON2ID, **ajustes: int) -> dict:
    """Crea parámetros nuevos con una sal aleatoria recién generada."""
    if nombre not in PREDETERMINADOS:
        raise ErrorKDF(f"KDF desconocido: {nombre!r}")
    parametros = {"nombre": nombre, **PREDETERMINADOS[nombre], **ajustes}
    # `secrets` usa el generador criptográfico del sistema operativo.
    parametros["sal"] = a_b64(secrets.token_bytes(LONGITUD_SAL))
    validar_parametros(parametros)
    return parametros


def validar_parametros(parametros: dict) -> None:
    """Comprueba tipos y rangos. Lanza ErrorKDF si algo no cuadra."""
    if not isinstance(parametros, dict):
        raise ErrorKDF("parámetros de KDF ausentes")
    nombre = parametros.get("nombre")
    if nombre not in PREDETERMINADOS:
        raise ErrorKDF(f"KDF desconocido: {nombre!r}")
    esperadas = set(PREDETERMINADOS[nombre]) | {"nombre", "sal"}
    if set(parametros) != esperadas:
        raise ErrorKDF("campos de KDF inesperados")
    for campo, maximo in MAXIMOS[nombre].items():
        valor = parametros[campo]
        # bool es subclase de int en Python: lo excluimos explícitamente.
        if not isinstance(valor, int) or isinstance(valor, bool) or valor < 1:
            raise ErrorKDF(f"{campo} debe ser un entero positivo")
        if valor > maximo:
            raise ErrorKDF(f"{campo} supera el máximo permitido ({maximo})")
    if nombre == ARGON2ID and parametros["memoria_kib"] < 8 * parametros["paralelismo"]:
        raise ErrorKDF("Argon2 exige memoria_kib >= 8 * paralelismo")
    try:
        sal = de_b64(parametros["sal"])
    except ErrorCodificacion as exc:
        raise ErrorKDF("sal inválida") from exc
    if len(sal) < LONGITUD_SAL:
        raise ErrorKDF(f"la sal debe tener al menos {LONGITUD_SAL} bytes")


def avisos_parametros(parametros: dict) -> list[str]:
    """Devuelve avisos si los parámetros son más débiles de lo recomendado."""
    nombre = parametros["nombre"]
    return [
        f"{campo}={parametros[campo]} está por debajo del mínimo recomendado ({minimo})"
        for campo, minimo in MINIMOS_RECOMENDADOS[nombre].items()
        if parametros[campo] < minimo
    ]


def derivar_clave(maestra: str, parametros: dict) -> bytes:
    """Deriva la clave AES-256 de 32 bytes."""
    validar_parametros(parametros)
    secreto = normalizar_maestra(maestra)
    sal = de_b64(parametros["sal"])
    if parametros["nombre"] == ARGON2ID:
        return hash_secret_raw(
            secret=secreto,
            salt=sal,
            time_cost=parametros["tiempo"],
            memory_cost=parametros["memoria_kib"],
            parallelism=parametros["paralelismo"],
            hash_len=LONGITUD_CLAVE,
            type=Type.ID,
        )
    return hashlib.pbkdf2_hmac(
        "sha256", secreto, sal, parametros["iteraciones"], dklen=LONGITUD_CLAVE
    )
