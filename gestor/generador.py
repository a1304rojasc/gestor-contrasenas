"""Generador de contraseñas y frases de paso.

Se usa SIEMPRE el módulo `secrets` (CSPRNG del sistema operativo). El módulo
`random` es un Mersenne Twister: rápido y bueno para simulaciones, pero
predecible: tras observar 624 salidas de 32 bits se puede reconstruir su
estado y predecir todas las siguientes.
"""

from __future__ import annotations

import math
import secrets
import string

from gestor.listas import palabras_diceware

MINUSCULAS = string.ascii_lowercase
MAYUSCULAS = string.ascii_uppercase
DIGITOS = string.digits
SIMBOLOS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
AMBIGUOS = set("Il1O0o")

LONGITUD_MINIMA = 8
LONGITUD_MAXIMA = 256


class ErrorGenerador(ValueError):
    pass


def clases_activas(simbolos: bool = True, sin_ambiguos: bool = False) -> list[str]:
    clases = [MINUSCULAS, MAYUSCULAS, DIGITOS] + ([SIMBOLOS] if simbolos else [])
    if sin_ambiguos:
        clases = ["".join(c for c in clase if c not in AMBIGUOS) for clase in clases]
    return clases


def generar_contrasena(longitud: int = 20, simbolos: bool = True, sin_ambiguos: bool = False) -> str:
    """Contraseña aleatoria con al menos un carácter de cada clase activa.

    Técnica: "muestreo con rechazo". Se genera una contraseña uniforme sobre
    el alfabeto completo y, si le falta alguna clase, se descarta entera y se
    genera otra. Así el resultado es uniforme entre todas las contraseñas
    válidas. (Forzar "una mayúscula en la posición 0" crearía sesgos.)
    """
    if not LONGITUD_MINIMA <= longitud <= LONGITUD_MAXIMA:
        raise ErrorGenerador(f"la longitud debe estar entre {LONGITUD_MINIMA} y {LONGITUD_MAXIMA}")
    clases = clases_activas(simbolos, sin_ambiguos)
    alfabeto = "".join(clases)
    while True:
        candidata = "".join(secrets.choice(alfabeto) for _ in range(longitud))
        if all(any(c in clase for c in candidata) for clase in clases):
            return candidata


def entropia_contrasena(longitud: int, simbolos: bool = True, sin_ambiguos: bool = False) -> float:
    """Entropía aproximada (bits) = longitud * log2(tamaño del alfabeto)."""
    alfabeto = "".join(clases_activas(simbolos, sin_ambiguos))
    return longitud * math.log2(len(alfabeto))


def generar_frase(palabras: int = 6, separador: str = "-", mayuscula: bool = False, numero: bool = False) -> str:
    """Frase tipo diceware: palabras elegidas al azar de una lista pública.

    La seguridad NO depende de que la lista sea secreta, sino de que cada
    palabra se elige uniformemente al azar: entropía = n * log2(tamaño lista).
    """
    if not 3 <= palabras <= 30:
        raise ErrorGenerador("el número de palabras debe estar entre 3 y 30")
    lista = palabras_diceware()
    elegidas = [secrets.choice(lista) for _ in range(palabras)]
    if mayuscula:
        i = secrets.randbelow(palabras)
        elegidas[i] = elegidas[i].capitalize()
    if numero:
        elegidas.append(str(secrets.randbelow(100)))
    return separador.join(elegidas)


def entropia_frase(palabras: int, mayuscula: bool = False, numero: bool = False) -> float:
    bits = palabras * math.log2(len(palabras_diceware()))
    if mayuscula:
        bits += math.log2(palabras)
    if numero:
        bits += math.log2(100)
    return bits
