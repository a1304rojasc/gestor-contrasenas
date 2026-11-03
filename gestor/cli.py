"""Interfaz de línea de comandos.

Reglas de seguridad de esta interfaz:
- Las contraseñas (maestra y de entradas) se piden con `getpass`: no se ven
  en pantalla y NUNCA se aceptan como argumento, porque los argumentos quedan
  en el historial del shell (~/.bash_history) y son visibles con `ps`.
- `obtener` copia al portapapeles y lo limpia pasados unos segundos; solo
  imprime la contraseña si se pide explícitamente con --mostrar.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from pathlib import Path

from gestor import __version__, fortaleza, generador, kdf, portapapeles
from gestor.boveda import Boveda, ErrorBoveda

RUTA_PREDETERMINADA = Path(os.environ.get("GESTOR_BOVEDA", Path.home() / ".gestor_boveda.json"))
AVISO_EDUCATIVO = "AVISO: herramienta EDUCATIVA. Para secretos reales usa Bitwarden o KeePassXC."


class ErrorUsuario(Exception):
    """Error provocado por la entrada del usuario (se muestra tal cual)."""


# ---------------------------------------------------------------------------
# Entrada / salida
# ---------------------------------------------------------------------------

def _err(*partes: object) -> None:
    print(*partes, file=sys.stderr)


def _pedir_secreto(mensaje: str, confirmar: bool = False) -> str:
    secreto = getpass.getpass(mensaje)
    if not secreto:
        raise ErrorUsuario("no se introdujo nada")
    if confirmar and getpass.getpass("Repítela: ") != secreto:
        raise ErrorUsuario("las contraseñas no coinciden")
    return secreto


def _confirmar(pregunta: str) -> bool:
    try:
        return input(f"{pregunta} [s/N] ").strip().lower() in ("s", "si", "sí", "y", "yes")
    except EOFError:
        return False


def _pedir_maestra_nueva() -> str:
    maestra = _pedir_secreto("Nueva contraseña maestra: ", confirmar=True)
    resultado = fortaleza.evaluar(maestra)
    _err(f"Fortaleza: {resultado.etiqueta} ({resultado.puntaje}/4, ~{resultado.bits:.0f} bits)")
    if resultado.puntaje < 3:
        for consejo in resultado.consejos:
            _err(f"  - {consejo}")
        if not _confirmar("La contraseña maestra es débil y protege TODO. ¿Usarla de todos modos?"):
            raise ErrorUsuario("operación cancelada")
    return maestra


def _parametros_kdf(nombre: str, ajustes_kdf: dict | None) -> dict:
    ajustes = (ajustes_kdf or {}).get(nombre, {})
    parametros = kdf.nuevos_parametros(nombre, **ajustes)
    for aviso in kdf.avisos_parametros(parametros):
        _err(f"Aviso KDF: {aviso}")
    return parametros


def _abrir(args: argparse.Namespace) -> Boveda:
    maestra = _pedir_secreto("Contraseña maestra: ")
    return Boveda.abrir(args.boveda, maestra)


# ---------------------------------------------------------------------------
# Comandos
# ---------------------------------------------------------------------------

def cmd_init(args, ajustes_kdf):
    if args.boveda.exists() and not args.forzar:
        raise ErrorUsuario(f"ya existe {args.boveda} (usa --forzar para sobrescribirla)")
    if args.boveda.exists() and not _confirmar(f"Se BORRARÁ {args.boveda} y todo su contenido. ¿Seguro?"):
        raise ErrorUsuario("operación cancelada")
    maestra = _pedir_maestra_nueva()
    _err(f"Derivando clave con {args.kdf} (puede tardar un poco)...")
    Boveda.crear(args.boveda, maestra, _parametros_kdf(args.kdf, ajustes_kdf), sobrescribir=args.forzar)
    print(f"Bóveda creada en {args.boveda} (permisos 0600).")


def cmd_agregar(args, _):
    boveda = _abrir(args)
    if args.generar:
        contrasena = generador.generar_contrasena(args.longitud, simbolos=not args.sin_simbolos)
        _err(f"Contraseña generada ({args.longitud} caracteres). Usa `obtener {args.nombre}` para copiarla.")
    else:
        contrasena = _pedir_secreto(f"Contraseña para {args.nombre!r}: ", confirmar=True)
        r = fortaleza.evaluar(contrasena, usar_zxcvbn=False)
        if r.puntaje < 2:
            _err(f"Aviso: contraseña {r.etiqueta}. Considera `agregar --generar`.")
    boveda.agregar(args.nombre, contrasena, args.usuario, args.url, args.notas, reemplazar=args.reemplazar)
    print(f"Entrada {args.nombre!r} guardada.")


def cmd_obtener(args, _):
    entrada = _abrir(args).obtener(args.nombre)
    for campo in ("usuario", "url", "notas"):
        if entrada.get(campo):
            print(f"{campo.capitalize()}: {entrada[campo]}")
    if args.mostrar:
        print(f"Contraseña: {entrada['contrasena']}")
        _err("(Recuerda: ahora está en el historial visual de tu terminal.)")
        return
    if not portapapeles.copiar(entrada["contrasena"]):
        raise ErrorUsuario("no hay portapapeles disponible (instala wl-copy/xclip/xsel) o usa --mostrar")
    _err(f"Contraseña copiada. Se borrará del portapapeles en {args.segundos} s (Ctrl+C para borrarla ya).")
    try:
        time.sleep(args.segundos)
    except KeyboardInterrupt:
        pass
    finally:
        portapapeles.limpiar()
    _err("Portapapeles limpiado.")


def cmd_listar(args, _):
    entradas = _abrir(args).listar()
    if not entradas:
        print("La bóveda está vacía.")
        return
    ancho = max(len(nombre) for nombre, _ in entradas)
    for nombre, e in entradas:
        extra = "  ".join(x for x in (e.get("usuario", ""), e.get("url", "")) if x)
        print(f"{nombre.ljust(ancho)}  {extra}".rstrip())


def cmd_eliminar(args, _):
    boveda = _abrir(args)
    boveda.obtener(args.nombre)
    if not args.si and not _confirmar(f"¿Eliminar {args.nombre!r}?"):
        raise ErrorUsuario("operación cancelada")
    boveda.eliminar(args.nombre)
    print(f"Entrada {args.nombre!r} eliminada.")


def cmd_generar(args, _):
    for _i in range(args.cantidad):
        if args.frase:
            print(generador.generar_frase(args.palabras, args.separador, args.mayuscula, args.numero))
        else:
            print(generador.generar_contrasena(args.longitud, not args.sin_simbolos, args.sin_ambiguos))
    if args.frase:
        bits = generador.entropia_frase(args.palabras, args.mayuscula, args.numero)
    else:
        bits = generador.entropia_contrasena(args.longitud, not args.sin_simbolos, args.sin_ambiguos)
    _err(f"Entropía: ~{bits:.0f} bits por {'frase' if args.frase else 'contraseña'}.")


def cmd_fortaleza(args, _):
    contrasena = _pedir_secreto("Contraseña a evaluar (no se mostrará): ")
    r = fortaleza.evaluar(contrasena, usar_zxcvbn=not args.sin_zxcvbn)
    print(f"Puntaje: {r.puntaje}/4 ({r.etiqueta})")
    print(f"Entropía estimada: ~{r.bits:.1f} bits (fuerza bruta pura: {fortaleza.entropia_fuerza_bruta(contrasena):.1f})")
    if r.patrones:
        print("Patrones detectados:")
        for p in r.patrones:
            print(f"  - {p.descripcion} (~{p.bits:.1f} bits)")
    print("Tiempo medio para adivinarla:")
    for escenario, tiempo in r.tiempos:
        print(f"  - {escenario}: {tiempo}")
    print("Consejos:")
    for consejo in r.consejos:
        print(f"  - {consejo}")
    if r.zxcvbn:
        print(f"zxcvbn: puntaje {r.zxcvbn['puntaje']}/4, ~{r.zxcvbn['bits']:.1f} bits")


def cmd_cambiar_maestra(args, ajustes_kdf):
    boveda = _abrir(args)
    nombre = args.kdf or boveda.kdf_parametros["nombre"]
    nueva = _pedir_maestra_nueva()
    _err(f"Re-cifrando con {nombre} y sal nueva...")
    boveda.cambiar_maestra(nueva, _parametros_kdf(nombre, ajustes_kdf))
    print(f"Contraseña maestra cambiada. {len(boveda.entradas)} entradas conservadas.")


# ---------------------------------------------------------------------------
# Argumentos
# ---------------------------------------------------------------------------

def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gestor", description="Gestor de contraseñas educativo (AES-256-GCM + Argon2id).", epilog=AVISO_EDUCATIVO)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-b", "--boveda", type=Path, default=RUTA_PREDETERMINADA, help=f"ruta de la bóveda (por defecto $GESTOR_BOVEDA o {RUTA_PREDETERMINADA})")
    sub = p.add_subparsers(dest="comando", required=True, metavar="COMANDO")

    s = sub.add_parser("init", help="crear una bóveda nueva")
    s.add_argument("--kdf", choices=[kdf.ARGON2ID, kdf.PBKDF2], default=kdf.ARGON2ID)
    s.add_argument("--forzar", action="store_true", help="sobrescribir una bóveda existente")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("agregar", help="añadir o reemplazar una entrada")
    s.add_argument("nombre")
    s.add_argument("-u", "--usuario", default="")
    s.add_argument("--url", default="")
    s.add_argument("--notas", default="", help="texto libre (¡no pongas secretos aquí: queda en el historial!)")
    s.add_argument("-g", "--generar", action="store_true", help="generar una contraseña aleatoria")
    s.add_argument("-l", "--longitud", type=int, default=20)
    s.add_argument("--sin-simbolos", action="store_true")
    s.add_argument("--reemplazar", action="store_true")
    s.set_defaults(func=cmd_agregar)

    s = sub.add_parser("obtener", help="copiar (o mostrar) una contraseña")
    s.add_argument("nombre")
    s.add_argument("-m", "--mostrar", action="store_true", help="imprimirla en pantalla en vez de copiarla")
    s.add_argument("-s", "--segundos", type=int, default=20, help="segundos antes de limpiar el portapapeles")
    s.set_defaults(func=cmd_obtener)

    s = sub.add_parser("listar", help="listar entradas (sin contraseñas)")
    s.set_defaults(func=cmd_listar)

    s = sub.add_parser("eliminar", help="eliminar una entrada")
    s.add_argument("nombre")
    s.add_argument("--si", action="store_true", help="no pedir confirmación")
    s.set_defaults(func=cmd_eliminar)

    s = sub.add_parser("generar", help="generar contraseñas o frases (no usa la bóveda)")
    s.add_argument("-l", "--longitud", type=int, default=20)
    s.add_argument("--sin-simbolos", action="store_true")
    s.add_argument("--sin-ambiguos", action="store_true", help="excluir I l 1 O 0 o")
    s.add_argument("-f", "--frase", action="store_true", help="frase tipo diceware en español")
    s.add_argument("-p", "--palabras", type=int, default=6)
    s.add_argument("--separador", default="-")
    s.add_argument("--mayuscula", action="store_true", help="poner en mayúscula una palabra al azar")
    s.add_argument("--numero", action="store_true", help="añadir un número al final")
    s.add_argument("-n", "--cantidad", type=int, default=1)
    s.set_defaults(func=cmd_generar)

    s = sub.add_parser("fortaleza", help="evaluar una contraseña (se pide de forma oculta)")
    s.add_argument("--sin-zxcvbn", action="store_true", help="no usar zxcvbn aunque esté instalado")
    s.set_defaults(func=cmd_fortaleza)

    s = sub.add_parser("cambiar-maestra", help="cambiar la contraseña maestra (re-cifra todo)")
    s.add_argument("--kdf", choices=[kdf.ARGON2ID, kdf.PBKDF2], help="cambiar también de KDF")
    s.set_defaults(func=cmd_cambiar_maestra)
    return p


def main(argv: list[str] | None = None, ajustes_kdf: dict | None = None) -> int:
    """Punto de entrada. `ajustes_kdf` solo lo usan los tests (KDF rápido)."""
    args = construir_parser().parse_args(argv)
    try:
        args.func(args, ajustes_kdf)
    except (ErrorBoveda, ErrorUsuario, kdf.ErrorKDF, generador.ErrorGenerador) as exc:
        _err(f"Error: {exc}")
        return 1
    except KeyboardInterrupt:
        _err("\nCancelado.")
        return 130
    return 0
