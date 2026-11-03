"""Pruebas de extremo a extremo de la CLI (getpass simulado)."""

import json

import pytest

from gestor import cli, portapapeles

MAESTRA = "una-maestra-bastante-larga-2"


@pytest.fixture
def teclado(monkeypatch):
    """Simula lo que la usuaria escribe en getpass e input."""
    respuestas = {"secretos": [], "confirmaciones": []}

    def falso_getpass(_mensaje=""):
        return respuestas["secretos"].pop(0)

    def falso_input(_mensaje=""):
        return respuestas["confirmaciones"].pop(0) if respuestas["confirmaciones"] else "n"

    monkeypatch.setattr(cli.getpass, "getpass", falso_getpass)
    monkeypatch.setattr("builtins.input", falso_input)
    return respuestas


def ejecutar(ruta, ajustes, *argv):
    return cli.main(["-b", str(ruta), *argv], ajustes_kdf=ajustes)


def test_flujo_completo(ruta, ajustes_kdf, teclado, capsys, monkeypatch):
    teclado["secretos"] += [MAESTRA, MAESTRA]
    assert ejecutar(ruta, ajustes_kdf, "init") == 0

    teclado["secretos"] += [MAESTRA, "clave-del-correo", "clave-del-correo"]
    assert ejecutar(ruta, ajustes_kdf, "agregar", "correo", "-u", "ana") == 0

    teclado["secretos"] += [MAESTRA]
    assert ejecutar(ruta, ajustes_kdf, "agregar", "banco", "--generar", "-l", "24") == 0

    teclado["secretos"] += [MAESTRA]
    assert ejecutar(ruta, ajustes_kdf, "listar") == 0
    salida = capsys.readouterr().out
    assert "correo" in salida and "banco" in salida and "clave-del-correo" not in salida

    teclado["secretos"] += [MAESTRA]
    assert ejecutar(ruta, ajustes_kdf, "obtener", "correo", "--mostrar") == 0
    assert "clave-del-correo" in capsys.readouterr().out

    copiado = []
    monkeypatch.setattr(portapapeles, "copiar", lambda t: copiado.append(t) or True)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    teclado["secretos"] += [MAESTRA]
    assert ejecutar(ruta, ajustes_kdf, "obtener", "correo") == 0
    assert copiado == ["clave-del-correo", ""]  # copiada y luego limpiada
    assert "clave-del-correo" not in capsys.readouterr().out

    nueva = "otra-maestra-distinta-y-larga-9"
    teclado["secretos"] += [MAESTRA, nueva, nueva]
    assert ejecutar(ruta, ajustes_kdf, "cambiar-maestra", "--kdf", "pbkdf2-sha256") == 0
    assert json.loads(ruta.read_text())["kdf"]["nombre"] == "pbkdf2-sha256"

    teclado["secretos"] += [nueva]
    assert ejecutar(ruta, ajustes_kdf, "eliminar", "banco", "--si") == 0

    teclado["secretos"] += [nueva]
    assert ejecutar(ruta, ajustes_kdf, "obtener", "correo", "-m") == 0
    assert "clave-del-correo" in capsys.readouterr().out


def test_maestra_incorrecta_error_claro(ruta, ajustes_kdf, teclado, capsys):
    teclado["secretos"] += [MAESTRA, MAESTRA]
    ejecutar(ruta, ajustes_kdf, "init")
    teclado["secretos"] += ["mala"]
    assert ejecutar(ruta, ajustes_kdf, "listar") == 1
    err = capsys.readouterr().err
    assert "incorrecta o el archivo ha sido modificado" in err
    assert "Traceback" not in err


def test_maestra_debil_se_puede_rechazar(ruta, ajustes_kdf, teclado):
    teclado["secretos"] += ["123456", "123456"]
    teclado["confirmaciones"] += ["n"]
    assert ejecutar(ruta, ajustes_kdf, "init") == 1
    assert not ruta.exists()


def test_confirmacion_distinta_falla(ruta, ajustes_kdf, teclado):
    teclado["secretos"] += [MAESTRA, MAESTRA + "x"]
    assert ejecutar(ruta, ajustes_kdf, "init") == 1


def test_no_acepta_contrasena_como_argumento():
    """Ningún subcomando tiene una opción para pasar contraseñas por argv."""
    parser = cli.construir_parser()
    sub = next(a for a in parser._actions if a.dest == "comando")
    for nombre, subparser in sub.choices.items():
        opciones = {o for a in subparser._actions for o in a.option_strings}
        assert not any("contrasena" in o or "maestra" in o or "password" in o for o in opciones), nombre


def test_generar_y_fortaleza(teclado, capsys):
    assert cli.main(["generar", "-n", "3", "-l", "16"]) == 0
    lineas = capsys.readouterr().out.split()
    assert len(lineas) == 3 and all(len(l) == 16 for l in lineas)
    teclado["secretos"] += ["123456"]
    assert cli.main(["fortaleza", "--sin-zxcvbn"]) == 0
    assert "0/4" in capsys.readouterr().out
