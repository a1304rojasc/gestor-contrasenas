import pytest

from gestor import fortaleza
from gestor.generador import generar_contrasena, generar_frase


@pytest.mark.parametrize("debil", ["123456", "password", "qwerty", "P@ssw0rd", "aaaaaaaa", "abcdefgh", "asdfghjk", "maria1990", "15/08/1990", "contraseña"])
def test_contrasenas_debiles_puntuan_bajo(debil):
    r = fortaleza.evaluar(debil, usar_zxcvbn=False)
    assert r.puntaje <= 1, (debil, r.bits)


def test_123456_es_la_peor():
    r = fortaleza.evaluar("123456", usar_zxcvbn=False)
    assert r.puntaje == 0
    assert r.bits < 5
    assert any(p.tipo == "común" for p in r.patrones)
    assert any("comunes" in c for c in r.consejos)


@pytest.mark.parametrize("fuerte", [
    "el loro verde de mi abuela canta tangos los domingos por la noche",
    "Mi perro Toby se comio 3 calcetines rojos en la playa!",
])
def test_frase_larga_puntua_alto(fuerte):
    assert fortaleza.evaluar(fuerte, usar_zxcvbn=False).puntaje == 4


def test_generadas_puntuan_alto():
    for _ in range(20):
        assert fortaleza.evaluar(generar_contrasena(20), usar_zxcvbn=False).puntaje == 4
        assert fortaleza.evaluar(generar_frase(7), usar_zxcvbn=False).puntaje >= 3


@pytest.mark.parametrize("texto,tipo", [
    ("xxmnopqrxx", "secuencia"),
    ("zzzzzzzz", "repetición"),
    ("Qwertyuiop", "teclado"),
    ("hola2024", "año"),
    ("p4ssw0rd", "leet"),
])
def test_detecta_patrones(texto, tipo):
    tipos = {p.tipo for p in fortaleza.evaluar(texto, usar_zxcvbn=False).patrones}
    assert tipo in tipos


def test_patrones_bajan_la_entropia():
    texto = "qwerty123456"
    assert fortaleza.estimar_bits(texto) < fortaleza.entropia_fuerza_bruta(texto) / 3


def test_tiempos_y_consejos_en_espanol():
    r = fortaleza.evaluar("abc", usar_zxcvbn=False)
    assert len(r.tiempos) == 3
    assert any("caracteres" in c for c in r.consejos)
    assert r.etiqueta == "muy débil"


def test_vacia():
    r = fortaleza.evaluar("", usar_zxcvbn=False)
    assert r.bits == 0 and r.puntaje == 0
