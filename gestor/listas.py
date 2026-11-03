"""Carga de las listas de palabras incluidas en `gestor/datos/`."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources


def _leer(nombre: str) -> list[str]:
    texto = resources.files("gestor").joinpath("datos", nombre).read_text(encoding="utf-8")
    palabras: list[str] = []
    vistas: set[str] = set()
    for linea in texto.splitlines():
        if linea.lstrip().startswith("#"):
            continue
        for palabra in linea.split():
            palabra = palabra.strip().lower()
            if palabra and palabra not in vistas:
                vistas.add(palabra)
                palabras.append(palabra)
    return palabras


@lru_cache(maxsize=None)
def palabras_diceware() -> tuple[str, ...]:
    return tuple(_leer("palabras_es.txt"))


@lru_cache(maxsize=None)
def contrasenas_comunes() -> dict[str, int]:
    """Devuelve {palabra: rango}; rango 0 = la más común."""
    return {p: i for i, p in enumerate(_leer("contrasenas_comunes.txt"))}
