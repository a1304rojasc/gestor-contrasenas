# gestor-contrasenas

[![tests](https://github.com/a1304rojasc/gestor-contrasenas/actions/workflows/tests.yml/badge.svg)](https://github.com/a1304rojasc/gestor-contrasenas/actions/workflows/tests.yml)

Gestor de contraseñas de línea de comandos en Python, hecho **para aprender
criptografía aplicada**: derivación de claves (Argon2id / PBKDF2), cifrado
autenticado (AES-256-GCM con datos asociados), generación segura de
contraseñas y estimación de su fortaleza.

> ## ⚠️ Esto es educativo
>
> Este proyecto **no ha sido auditado** y no tiene las protecciones de un
> producto real (sincronización segura, protección de memoria, integración
> con el navegador, recuperación, auditorías externas...).
> **Para tus contraseñas reales usa [Bitwarden](https://bitwarden.com/) o
> [KeePassXC](https://keepassxc.org/).**
> Úsalo para leer el código, romperlo, hacer experimentos y entender por qué
> los gestores de verdad están diseñados como lo están.

La explicación de cada decisión de diseño está en
**[CRIPTOGRAFIA.md](CRIPTOGRAFIA.md)**.

---

## Instalación

Requiere Python 3.10 o superior.

```bash
git clone https://github.com/a1304rojasc/gestor-contrasenas.git
cd gestor-contrasenas
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# Opcional: segundo medidor de fortaleza
pip install zxcvbn
```

Para copiar al portapapeles se usa la herramienta del sistema: `wl-copy`
(Wayland), `xclip` o `xsel` (X11), `pbcopy` (macOS) o `clip.exe` (Windows).

## Uso

```bash
python -m gestor COMANDO [opciones]
```

La bóveda se guarda en `~/.gestor_boveda.json`. Puedes cambiarla con
`-b ruta` (antes del comando) o con la variable de entorno `GESTOR_BOVEDA`.

| Comando | Qué hace |
|---|---|
| `init [--kdf argon2id\|pbkdf2-sha256]` | Crea una bóveda nueva. Pide la maestra dos veces y avisa si es débil. |
| `agregar NOMBRE [-u USUARIO] [--url URL] [--notas TXT] [--generar -l 24] [--reemplazar]` | Añade una entrada. La contraseña se pide oculta o se genera. |
| `obtener NOMBRE [--mostrar] [-s 20]` | Copia la contraseña al portapapeles y lo limpia a los 20 s. `--mostrar` la imprime. |
| `listar` | Lista nombres, usuarios y URLs (nunca contraseñas). |
| `eliminar NOMBRE [--si]` | Borra una entrada (pide confirmación). |
| `generar [-l 20] [--sin-simbolos] [--sin-ambiguos] [-n 5]` | Genera contraseñas aleatorias. |
| `generar --frase [-p 6] [--separador -] [--mayuscula] [--numero]` | Genera una frase tipo diceware en español. |
| `fortaleza [--sin-zxcvbn]` | Evalúa una contraseña (se pide oculta): entropía, patrones, tiempos y consejos. |
| `cambiar-maestra [--kdf ...]` | Cambia la maestra (y opcionalmente el KDF). Re-cifra todo con sal nueva. |

### Ejemplo

```text
$ python -m gestor init
Nueva contraseña maestra:
Repítela:
Fortaleza: muy fuerte (4/4, ~95 bits)
Derivando clave con argon2id (puede tardar un poco)...
Bóveda creada en /home/ana/.gestor_boveda.json (permisos 0600).

$ python -m gestor agregar correo -u ana@ejemplo.org --generar -l 24
Contraseña maestra:
Contraseña generada (24 caracteres). Usa `obtener correo` para copiarla.
Entrada 'correo' guardada.

$ python -m gestor obtener correo
Contraseña maestra:
Usuario: ana@ejemplo.org
Contraseña copiada. Se borrará del portapapeles en 20 s (Ctrl+C para borrarla ya).

$ python -m gestor generar --frase -p 6
mula-sandia-perla-ambar-pantera-pulga
Entropía: ~59 bits por frase.

$ python -m gestor fortaleza
Contraseña a evaluar (no se mostrará):
Puntaje: 0/4 (muy débil)
Entropía estimada: ~10.5 bits (fuerza bruta pura: 51.7)
Patrones detectados:
  - 'qwerty' es una contraseña muy común (~2.8 bits)
  - '2024' parece un año (~7.6 bits)
Tiempo medio para adivinarla:
  - ataque en línea (con límite de intentos): 1 minuto
  - fuera de línea contra Argon2id/PBKDF2 bien configurado: instantáneo
  - fuera de línea contra un hash rápido (MD5/SHA-1) con GPUs: instantáneo
Consejos:
  - Usa al menos 12-16 caracteres: la longitud es lo que más aporta.
  - Evita contraseñas comunes: los atacantes las prueban primero.
  - Evita años y fechas (cumpleaños, aniversarios): son fáciles de adivinar.
```

### Por qué la contraseña nunca va como argumento

`python -m gestor agregar correo --password hunter2` dejaría `hunter2` en
`~/.bash_history` y visible para otros usuarios con `ps`. Por eso **todas**
las contraseñas se piden con `getpass` (sin eco en pantalla). Un test
comprueba que ningún comando tiene una opción así.

## Formato de la bóveda

```json
{
  "formato": "gestor-contrasenas-educativo",
  "version": 1,
  "kdf": {"nombre": "argon2id", "sal": "…b64…", "tiempo": 3, "memoria_kib": 65536, "paralelismo": 4},
  "cifrado": {"algoritmo": "AES-256-GCM", "nonce": "…b64 (12 bytes)…"},
  "metadatos": {"creada": "2026-11-03T16:00:00+00:00", "modificada": "…"},
  "texto_cifrado": "…b64 (JSON de entradas cifrado + etiqueta de 16 bytes)…"
}
```

- Todo excepto `texto_cifrado` es la **cabecera**: va en claro pero está
  autenticada como AAD. Cambiar un solo byte hace fallar el descifrado.
- Los nombres de las entradas, usuarios, URLs y notas van **dentro** del
  texto cifrado: el archivo no revela qué cuentas tienes.
- Se escribe de forma atómica (temporal + `fsync` + `os.replace`) con
  permisos `0600`.

## Estructura del código

```
gestor/
  kdf.py           Argon2id / PBKDF2, sal, validación de parámetros
  boveda.py        formato JSON, AES-256-GCM + AAD, escritura atómica, API Boveda
  generador.py     contraseñas y frases diceware con `secrets`
  fortaleza.py     medidor propio: patrones + programación dinámica
  cli.py           comandos (argparse + getpass)
  portapapeles.py  copiar/limpiar el portapapeles sin dependencias
  listas.py        carga de listas de palabras
  datos/
    palabras_es.txt           ~870 palabras en español (sin tildes) para diceware
    contrasenas_comunes.txt   lista corta de contraseñas comunes
tests/             pytest (KDF con parámetros rápidos SOLO en tests)
```

## Tests

```bash
python -m pytest
```

Cubren, entre otras cosas: ida y vuelta cifrar/descifrar, maestra incorrecta,
un byte cambiado en el texto cifrado, en el nonce o en la cabecera, nonces
que nunca se repiten, sal distinta por bóveda, permisos `0600`, escritura
atómica ante fallos, reglas del generador, puntuación del medidor
(`123456` bajo, frase larga alto), `cambiar-maestra` conservando entradas y
el flujo completo de la CLI.

Los tests usan parámetros de KDF **deliberadamente inseguros**
(`tests/conftest.py`) para tardar milisegundos. Los valores reales
(Argon2id t=3, 64 MiB, p=4; PBKDF2 600 000 iteraciones) están en
`gestor/kdf.py`.

## Ideas para seguir aprendiendo

- Añade un campo `version: 2` con otro algoritmo (p. ej. XChaCha20-Poly1305)
  y escribe la migración.
- Mide cuánto tarda Argon2id con distintos `memoria_kib` en tu equipo.
- Intenta "romper" tu propia bóveda: cambia bytes, reordena campos, copia la
  cabecera de otra bóveda... y comprueba qué detecta y por qué.
- Compara el medidor propio con `zxcvbn` en tu lista de ejemplos.

## Licencia

Uso educativo. Sin garantía de ningún tipo.
