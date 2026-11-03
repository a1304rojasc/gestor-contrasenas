"""Medidor de fortaleza de contraseñas (propio, educativo).

Idea (simplificada de zxcvbn): un atacante no prueba combinaciones al azar,
prueba primero lo PROBABLE: contraseñas comunes, palabras, secuencias,
filas del teclado, años... Por eso:

1. Se buscan PATRONES dentro de la contraseña. Cada patrón tiene un "coste"
   en bits: cuántos intentos (log2) necesita un atacante que conoce ese
   patrón para acertar ese trozo.
2. Los caracteres que no encajan en ningún patrón se consideran fuerza bruta:
   log2(tamaño del alfabeto usado) bits cada uno.
3. Con programación dinámica se elige la forma de "trocear" la contraseña que
   da MENOS bits (la más favorable para el atacante). Esa es la estimación.

Es una aproximación: sirve para aprender, no es un análisis exhaustivo.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from gestor.listas import contrasenas_comunes, palabras_diceware

ETIQUETAS = ("muy débil", "débil", "aceptable", "fuerte", "muy fuerte")
UMBRALES_BITS = (25, 40, 60, 80)  # límites entre puntajes 0|1|2|3|4

FILAS_TECLADO = (
    "1234567890", "qwertyuiop", "asdfghjklñ", "zxcvbnm",
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik,", "9ol.", "0pñ-",
)
TECLAS_TOTALES = 47

LEET = {"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t"}

# Intentos por segundo de distintos escenarios de ataque.
ESCENARIOS = (
    ("ataque en línea (con límite de intentos)", 10),
    ("fuera de línea contra Argon2id/PBKDF2 bien configurado", 1e4),
    ("fuera de línea contra un hash rápido (MD5/SHA-1) con GPUs", 1e10),
)


@dataclass
class Patron:
    inicio: int
    fin: int
    bits: float
    tipo: str
    descripcion: str


@dataclass
class Resultado:
    contrasena_longitud: int
    bits: float
    puntaje: int
    etiqueta: str
    patrones: list[Patron] = field(default_factory=list)
    consejos: list[str] = field(default_factory=list)
    tiempos: list[tuple[str, str]] = field(default_factory=list)
    zxcvbn: dict | None = None


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def tamano_alfabeto(texto: str) -> int:
    """Tamaño del alfabeto que un atacante de fuerza bruta tendría que usar."""
    tamano = 0
    if any(c.islower() and c.isascii() for c in texto):
        tamano += 26
    if any(c.isupper() and c.isascii() for c in texto):
        tamano += 26
    if any(c.isdigit() and c.isascii() for c in texto):
        tamano += 10
    if any(not c.isalnum() and c.isascii() for c in texto):
        tamano += 33
    if any(not c.isascii() for c in texto):
        tamano += 100  # ñ, tildes, emojis...
    return max(tamano, 1)


def entropia_fuerza_bruta(texto: str) -> float:
    return len(texto) * math.log2(tamano_alfabeto(texto))


def _sin_leet(texto: str) -> str:
    return "".join(LEET.get(c, c) for c in texto.lower())


def formatear_tiempo(segundos: float) -> str:
    if segundos < 1:
        return "instantáneo"
    unidades = (("siglos", 3.15e9), ("años", 3.15e7), ("días", 86400), ("horas", 3600), ("minutos", 60), ("segundos", 1))
    for nombre, valor in unidades:
        if segundos >= valor:
            cantidad = segundos / valor
            if nombre == "siglos" and cantidad > 1e6:
                return "más que la edad del universo" if cantidad > 1.4e8 else f"{cantidad:.1e} siglos"
            return f"{cantidad:,.0f} {nombre}".replace(",", ".")
    return "instantáneo"


# ---------------------------------------------------------------------------
# Detectores de patrones
# ---------------------------------------------------------------------------

def _diccionario(texto: str) -> list[Patron]:
    comunes = contrasenas_comunes()
    palabras = set(palabras_diceware())
    bits_palabra = math.log2(len(palabras))
    patrones = []
    n = len(texto)
    minusc = texto.lower()
    normal = _sin_leet(texto)
    for i in range(n):
        for j in range(i + 3, min(n, i + 40) + 1):
            trozo = texto[i:j]
            extra = 1.0 if trozo != trozo.lower() else 0.0  # mayúsculas
            candidatos = []
            for variante, extra_leet in ((minusc[i:j], 0.0), (normal[i:j], 1.0)):
                for forma, extra_rev in ((variante, 0.0), (variante[::-1], 1.0)):
                    if forma in comunes:
                        candidatos.append((math.log2(comunes[forma] + 2) + extra + extra_leet + extra_rev, "común", forma, extra_leet, extra_rev))
                    if forma in palabras:
                        candidatos.append((bits_palabra + extra + extra_leet + extra_rev, "palabra", forma, extra_leet, extra_rev))
            if candidatos:
                bits, tipo, forma, leet, rev = min(candidatos)
                desc = f"'{trozo}' es una contraseña muy común" if tipo == "común" else f"'{trozo}' es una palabra del diccionario"
                if leet:
                    desc += " (con sustituciones tipo a→@)"
                if rev:
                    desc += " (escrita al revés)"
                patrones.append(Patron(i, j, bits, "leet" if leet else tipo, desc))
    return patrones


def _secuencias(texto: str) -> list[Patron]:
    patrones = []
    n, i = len(texto), 0
    while i < n - 2:
        delta = ord(texto[i + 1]) - ord(texto[i])
        j = i + 1
        if delta in (1, -1):
            while j < n and ord(texto[j]) - ord(texto[j - 1]) == delta and texto[j].isalnum() and texto[j].isascii():
                j += 1
        if j - i >= 3 and texto[i].isalnum() and texto[i].isascii():
            trozo = texto[i:j]
            base = 10 if trozo.isdigit() else 26
            bits = math.log2(base) + math.log2(len(trozo)) + (1 if delta == -1 else 0)
            patrones.append(Patron(i, j, bits, "secuencia", f"'{trozo}' es una secuencia"))
            i = j - 1
        else:
            i += 1
    return patrones


def _repeticiones(texto: str) -> list[Patron]:
    patrones = []
    for m in re.finditer(r"(.)\1{2,}", texto):
        bits = math.log2(tamano_alfabeto(m.group(1))) + math.log2(len(m.group(0)))
        patrones.append(Patron(m.start(), m.end(), bits, "repetición", f"'{m.group(0)}' repite un carácter"))
    for m in re.finditer(r"(.{2,}?)\1+", texto):
        bloque = m.group(1)
        veces = len(m.group(0)) // len(bloque)
        bits = estimar_bits(bloque) + math.log2(veces)
        patrones.append(Patron(m.start(), m.end(), bits, "repetición", f"'{m.group(0)}' repite el bloque '{bloque}'"))
    return patrones


def _teclado(texto: str) -> list[Patron]:
    patrones = []
    minusc = texto.lower()
    n = len(texto)
    for i in range(n):
        mejor = None
        for j in range(i + 3, n + 1):
            trozo = minusc[i:j]
            al_reves = trozo[::-1]
            if any(trozo in fila for fila in FILAS_TECLADO):
                mejor = (j, 0)
            elif any(al_reves in fila for fila in FILAS_TECLADO):
                mejor = (j, 1)
            else:
                break
        if mejor:
            j, rev = mejor
            bits = math.log2(TECLAS_TOTALES) + math.log2(j - i) + rev
            patrones.append(Patron(i, j, bits, "teclado", f"'{texto[i:j]}' es un patrón de teclado"))
    return patrones


_FECHA = re.compile(r"(\d{1,2})[-/.]?(\d{1,2})[-/.]?((?:19|20)?\d{2})")


def _fechas(texto: str) -> list[Patron]:
    patrones = []
    for m in re.finditer(r"(?=((?:19|20)\d{2}))", texto):
        i = m.start()
        patrones.append(Patron(i, i + 4, math.log2(200), "año", f"'{m.group(1)}' parece un año"))
    n = len(texto)
    for i in range(n):
        for j in range(i + 4, min(n, i + 10) + 1):
            m = _FECHA.fullmatch(texto, i, j)
            if not m:
                continue
            a, b = int(m.group(1)), int(m.group(2))
            if (1 <= a <= 31 and 1 <= b <= 12) or (1 <= b <= 31 and 1 <= a <= 12):
                patrones.append(Patron(i, j, math.log2(31 * 12 * 200), "fecha", f"'{texto[i:j]}' parece una fecha"))
    return patrones


# ---------------------------------------------------------------------------
# Estimación
# ---------------------------------------------------------------------------

def _mejor_segmentacion(texto: str) -> tuple[float, list[Patron]]:
    n = len(texto)
    if n == 0:
        return 0.0, []
    bits_caracter = math.log2(tamano_alfabeto(texto))
    patrones = _diccionario(texto) + _secuencias(texto) + _repeticiones(texto) + _teclado(texto) + _fechas(texto)
    por_fin: dict[int, list[Patron]] = {}
    for p in patrones:
        por_fin.setdefault(p.fin, []).append(p)
    mejor = [0.0] + [math.inf] * n
    usado: list[Patron | None] = [None] * (n + 1)
    for k in range(1, n + 1):
        mejor[k] = mejor[k - 1] + bits_caracter
        for p in por_fin.get(k, []):
            if mejor[p.inicio] + p.bits < mejor[k]:
                mejor[k] = mejor[p.inicio] + p.bits
                usado[k] = p
    elegidos, k = [], n
    while k > 0:
        p = usado[k]
        if p is None:
            k -= 1
        else:
            elegidos.append(p)
            k = p.inicio
    return mejor[n], list(reversed(elegidos))


def estimar_bits(texto: str) -> float:
    return _mejor_segmentacion(texto)[0]


def puntaje_de_bits(bits: float) -> int:
    return sum(bits >= u for u in UMBRALES_BITS)


def _consejos(texto: str, puntaje: int, patrones: list[Patron]) -> list[str]:
    tipos = {p.tipo for p in patrones}
    consejos = []
    if len(texto) < 12:
        consejos.append("Usa al menos 12-16 caracteres: la longitud es lo que más aporta.")
    if "común" in tipos:
        consejos.append("Evita contraseñas comunes: los atacantes las prueban primero.")
    if "palabra" in tipos and puntaje < 3:
        consejos.append("Una sola palabra de diccionario es débil; mejor varias palabras al azar (usa `generar --frase`).")
    if "leet" in tipos:
        consejos.append("Cambiar letras por símbolos (a→@, o→0) no engaña a los programas de ataque.")
    if "secuencia" in tipos:
        consejos.append("Evita secuencias como 'abc' o '123'.")
    if "repetición" in tipos:
        consejos.append("Evita repetir caracteres o bloques ('aaa', 'abcabc').")
    if "teclado" in tipos:
        consejos.append("Evita patrones del teclado como 'qwerty' o 'asdf'.")
    if tipos & {"año", "fecha"}:
        consejos.append("Evita años y fechas (cumpleaños, aniversarios): son fáciles de adivinar.")
    if puntaje < 3 and tamano_alfabeto(texto) < 60 and not patrones:
        consejos.append("Combina minúsculas, mayúsculas, números y símbolos, o alarga la contraseña.")
    if puntaje >= 3:
        consejos.append("Buena contraseña. No la reutilices en otros sitios.")
    elif not consejos:
        consejos.append("Alárgala o genera una aleatoria con `generar`.")
    return consejos


def evaluar_zxcvbn(texto: str) -> dict | None:
    """Usa la librería zxcvbn si está instalada (opcional)."""
    try:
        from zxcvbn import zxcvbn  # type: ignore
    except ImportError:
        return None
    r = zxcvbn(texto[:100])  # zxcvbn es lento con entradas muy largas
    return {"puntaje": r["score"], "bits": math.log2(max(float(r["guesses"]), 1.0))}


def evaluar(texto: str, usar_zxcvbn: bool = True) -> Resultado:
    bits, patrones = _mejor_segmentacion(texto)
    puntaje = puntaje_de_bits(bits)
    # Intentos medios = la mitad del espacio de búsqueda.
    intentos = 2 ** max(bits - 1, 0)
    tiempos = [(nombre, formatear_tiempo(intentos / velocidad)) for nombre, velocidad in ESCENARIOS]
    return Resultado(
        contrasena_longitud=len(texto),
        bits=bits,
        puntaje=puntaje,
        etiqueta=ETIQUETAS[puntaje],
        patrones=patrones,
        consejos=_consejos(texto, puntaje, patrones),
        tiempos=tiempos,
        zxcvbn=evaluar_zxcvbn(texto) if usar_zxcvbn else None,
    )
