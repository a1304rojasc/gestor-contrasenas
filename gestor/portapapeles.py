"""Copiar al portapapeles sin dependencias extra.

La contraseña se pasa por la ENTRADA ESTÁNDAR del programa auxiliar, nunca
como argumento: los argumentos de un proceso son visibles para otros
usuarios con `ps` y pueden quedar en registros.
"""

from __future__ import annotations

import shutil
import subprocess

COMANDOS = (
    ("wl-copy",),                          # Linux Wayland
    ("xclip", "-selection", "clipboard"),  # Linux X11
    ("xsel", "--clipboard", "--input"),    # Linux X11
    ("pbcopy",),                           # macOS
    ("clip.exe",),                         # Windows / WSL
)


def _comando() -> tuple[str, ...] | None:
    for comando in COMANDOS:
        if shutil.which(comando[0]):
            return comando
    return None


def disponible() -> bool:
    return _comando() is not None


def copiar(texto: str) -> bool:
    """Devuelve True si se pudo copiar."""
    comando = _comando()
    if comando is None:
        return False
    try:
        # clip.exe espera UTF-16; el resto, UTF-8.
        codificacion = "utf-16-le" if comando[0] == "clip.exe" else "utf-8"
        subprocess.run(comando, input=texto.encode(codificacion), check=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def limpiar() -> bool:
    return copiar("")
