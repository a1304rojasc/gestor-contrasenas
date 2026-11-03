"""Utilidades de base64 estrictas.

`validate=True` hace que cualquier carácter fuera del alfabeto base64 sea un
error, en lugar de ignorarse en silencio (comportamiento por defecto de
Python). Así un archivo manipulado no "se arregla solo" al decodificar.
"""

import base64
import binascii


class ErrorCodificacion(ValueError):
    """El texto no es base64 válido."""


def a_b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def de_b64(texto: str) -> bytes:
    if not isinstance(texto, str):
        raise ErrorCodificacion("se esperaba una cadena base64")
    try:
        return base64.b64decode(texto.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ErrorCodificacion("base64 inválido") from exc
