import math
import string

import pytest

from gestor import generador
from gestor.listas import palabras_diceware


@pytest.mark.parametrize("longitud", [8, 12, 20, 64])
def test_longitud_y_clases(longitud):
    for _ in range(200):
        c = generador.generar_contrasena(longitud)
        assert len(c) == longitud
        assert any(x in string.ascii_lowercase for x in c)
        assert any(x in string.ascii_uppercase for x in c)
        assert any(x in string.digits for x in c)
        assert any(x in generador.SIMBOLOS for x in c)


def test_sin_simbolos():
    for _ in range(200):
        assert generador.generar_contrasena(16, simbolos=False).isalnum()


def test_sin_ambiguos():
    for _ in range(200):
        assert not set(generador.generar_contrasena(30, sin_ambiguos=True)) & generador.AMBIGUOS


def test_no_se_repiten():
    assert len({generador.generar_contrasena(16) for _ in range(1000)}) == 1000


@pytest.mark.parametrize("longitud", [0, 7, 257])
def test_longitud_invalida(longitud):
    with pytest.raises(generador.ErrorGenerador):
        generador.generar_contrasena(longitud)


def test_distribucion_aproximadamente_uniforme():
    alfabeto = "".join(generador.clases_activas())
    cuenta = {c: 0 for c in alfabeto}
    for _ in range(400):
        for c in generador.generar_contrasena(50):
            cuenta[c] += 1
    esperado = 400 * 50 / len(alfabeto)
    assert all(0.5 * esperado < v < 1.5 * esperado for v in cuenta.values())


def test_frase_diceware():
    lista = set(palabras_diceware())
    assert len(lista) >= 500
    for _ in range(100):
        frase = generador.generar_frase(6, separador=" ")
        palabras = frase.split(" ")
        assert len(palabras) == 6
        assert all(p in lista for p in palabras)


def test_frase_opciones():
    f = generador.generar_frase(5, separador=".", mayuscula=True, numero=True)
    partes = f.split(".")
    assert len(partes) == 6 and partes[-1].isdigit()
    assert sum(p[0].isupper() for p in partes[:-1]) == 1


def test_lista_sin_tildes():
    assert all(p.isascii() and p.isalpha() for p in palabras_diceware())


def test_entropia():
    assert generador.entropia_contrasena(20) == pytest.approx(20 * math.log2(len("".join(generador.clases_activas()))))
    assert generador.entropia_frase(6) == pytest.approx(6 * math.log2(len(palabras_diceware())))


def test_no_usa_random():
    import inspect
    fuente = inspect.getsource(generador)
    assert "import random" not in fuente
