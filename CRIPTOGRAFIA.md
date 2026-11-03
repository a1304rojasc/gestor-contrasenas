# Criptografía del gestor: qué se hace y por qué

Este documento explica cada decisión de diseño y **qué error común evita**.
Léelo junto al código: cada sección indica el archivo donde está.

> ## ⚠️ Esto es educativo
>
> El objetivo es aprender. Este código no está auditado, Python no permite
> proteger bien los secretos en memoria y faltan muchas defensas de un
> producto real. **Para uso real usa [Bitwarden](https://bitwarden.com/) o
> [KeePassXC](https://keepassxc.org/)**, que están auditados, mantenidos por
> equipos de seguridad y probados por millones de personas.

## Índice

1. [Visión general](#1-visión-general)
2. [KDF: por qué lento y con memoria](#2-kdf-por-qué-lento-y-con-memoria)
3. [Argon2id frente a PBKDF2](#3-argon2id-frente-a-pbkdf2)
4. [La sal](#4-la-sal)
5. [AES-256-GCM y no AES-CBC/ECB](#5-aes-256-gcm-y-no-aes-cbcecb)
6. [El nonce nunca debe repetirse](#6-el-nonce-nunca-debe-repetirse)
7. [Qué protege el AAD](#7-qué-protege-el-aad)
8. [Errores: InvalidTag sin filtrar datos](#8-errores-invalidtag-sin-filtrar-datos)
9. [`secrets` y no `random`](#9-secrets-y-no-random)
10. [Escritura atómica y permisos 0600](#10-escritura-atómica-y-permisos-0600)
11. [La interfaz: getpass, historial y portapapeles](#11-la-interfaz-getpass-historial-y-portapapeles)
12. [El medidor de fortaleza](#12-el-medidor-de-fortaleza)
13. [Modelo de amenazas](#13-modelo-de-amenazas)
14. [Tabla resumen de errores evitados](#14-tabla-resumen-de-errores-evitados)

---

## 1. Visión general

```
contraseña maestra ──NFC──▶ Argon2id(sal, t, m, p) ──▶ clave de 256 bits
                                                         │
cabecera (versión, kdf, sal, nonce, metadatos) ──AAD──┐  │
                                                      ▼  ▼
JSON con las entradas ─────────────────────▶ AES-256-GCM(nonce aleatorio)
                                                      │
                                                      ▼
                                   texto cifrado + etiqueta (16 bytes)
```

- **Confidencialidad**: nadie sin la maestra puede leer las entradas.
- **Integridad y autenticidad**: nadie sin la maestra puede modificar ni el
  contenido ni la cabecera sin que se detecte.
- Una **sola** clave cifra todo el JSON. Es más simple que cifrar cada
  entrada por separado y además oculta cuántas entradas hay y cómo se llaman
  (solo se ve el tamaño total aproximado).

## 2. KDF: por qué lento y con memoria

*Archivo: `gestor/kdf.py`*

Una contraseña humana no es una clave: tiene poca entropía (quizá 40–80
bits) y longitud variable. AES necesita exactamente 32 bytes aleatorios.

**Error común:** `clave = sha256(maestra)`. SHA-256 es rapidísimo: una GPU
moderna calcula **miles de millones** por segundo. Si alguien roba el
archivo, puede probar diccionarios enteros en minutos.

Un **KDF de contraseñas** (Key Derivation Function) es lento a propósito:

- Para ti, abrir la bóveda cuesta ~0,1–1 s **una vez**. No lo notas.
- Para el atacante, **cada intento** cuesta lo mismo. Si pasas de 10¹⁰ a 10⁴
  intentos/s, una contraseña que caía en un segundo ahora tarda 11 días.

El coste en **memoria** importa tanto como el de tiempo: las GPUs y ASICs
tienen miles de núcleos pero poca memoria por núcleo. Si cada intento
necesita 64 MiB, el atacante no puede ejecutar miles en paralelo; su ventaja
de hardware se desploma. A eso se le llama función *memory-hard*.

Los parámetros se guardan en la bóveda (no son secretos) para poder
**endurecerlos en el futuro**: `cambiar-maestra --kdf argon2id` vuelve a
derivar con los valores actuales del código y una sal nueva. Además se
validan con **máximos**: un archivo manipulado que pida 1 TiB de RAM se
rechaza antes de ejecutar el KDF (evita una denegación de servicio).

La maestra se **normaliza a NFC** antes de convertirla a bytes. "ñ" puede
escribirse como un carácter (U+00F1) o como "n" + tilde combinada
(U+006E U+0303); se ven igual pero sin normalizar darían claves distintas y
podrías quedarte fuera de tu bóveda al cambiar de teclado o sistema.

## 3. Argon2id frente a PBKDF2

| | Argon2id (predeterminado) | PBKDF2-HMAC-SHA256 (alternativa) |
|---|---|---|
| Año | 2015 (ganó la Password Hashing Competition), RFC 9106 | 2000, RFC 8018 |
| Coste en tiempo | Sí (`tiempo`) | Sí (`iteraciones`) |
| Coste en memoria | **Sí** (`memoria_kib`) | No (usa unos pocos bytes) |
| Resistencia a GPU/ASIC | Alta | Baja: se paraleliza perfectamente |
| Disponibilidad | Librería externa (`argon2-cffi`) | Biblioteca estándar (`hashlib`) y FIPS |
| Parámetros aquí | t=3, m=64 MiB, p=4 (RFC 9106, 2ª opción) | 600 000 iteraciones (OWASP 2023) |

**Por qué Argon2id y no Argon2i o Argon2d:** Argon2d es más resistente a
GPUs pero su acceso a memoria depende de la contraseña (posibles ataques de
canal lateral por caché). Argon2i es independiente de los datos pero más
débil frente a ciertos ataques de compromiso tiempo-memoria. **Argon2id**
combina ambos y es el recomendado por el RFC 9106 y OWASP.

**Por qué ofrecer PBKDF2:** está en la biblioteca estándar, es el único
aprobado por FIPS 140 y sirve para comparar. Con 600 000 iteraciones es
aceptable, pero un atacante con GPUs avanza mucho más rápido que con
Argon2id. Si lo usas, compénsalo con una maestra más larga.

**Error común:** copiar parámetros de un tutorial de 2010 (PBKDF2 con 1 000
iteraciones). Por eso el programa avisa si los parámetros están por debajo de
los mínimos recomendados.

## 4. La sal

*Archivo: `gestor/kdf.py` (`nuevos_parametros`)*

Cada bóveda tiene una **sal aleatoria de 16 bytes** (`secrets.token_bytes`).
Se guarda en claro en la cabecera.

Sin sal, `KDF("hola123")` daría siempre la misma clave. Eso permite:

- **Tablas precalculadas** (rainbow tables): calcular una vez las claves de
  millones de contraseñas y reutilizarlas contra cualquier víctima.
- **Atacar muchas bóvedas a la vez**: cada intento sirve contra todas.
- **Detectar maestras iguales**: dos bóvedas con la misma maestra tendrían la
  misma clave.

Con sal, el atacante tiene que empezar de cero para **cada** bóveda. 16
bytes (128 bits) garantizan en la práctica que nunca se repiten.
`cambiar-maestra` genera también una sal nueva.

**Error común:** usar una sal fija en el código, o el nombre de usuario como
sal (se repite entre servicios y es predecible).

## 5. AES-256-GCM y no AES-CBC/ECB

*Archivo: `gestor/boveda.py` (`cifrar_documento`, `descifrar_documento`)*

AES es un cifrado de **bloque**: transforma 16 bytes en 16 bytes. Para
cifrar más datos hace falta un **modo de operación**, y ahí se cometen la
mayoría de los errores.

- **ECB** cifra cada bloque por separado: bloques iguales → cifrados iguales.
  Se ven los patrones (el famoso "pingüino de Linux en ECB"). Nunca lo uses.
- **CBC** oculta los patrones, pero **solo da confidencialidad**: un atacante
  puede modificar el texto cifrado y el descifrado "funciona" con datos
  alterados. Combinado con mensajes de error distintos permite el ataque de
  *padding oracle* (descifrar sin la clave). Para hacerlo seguro hay que
  añadir un MAC aparte (encrypt-then-MAC), y es fácil equivocarse en el orden
  o en qué se autentica.
- **GCM** es un modo **AEAD** (*Authenticated Encryption with Associated
  Data*): cifra (en modo contador, sin relleno) **y** calcula una etiqueta de
  autenticación de 128 bits sobre el texto cifrado y los datos asociados. Al
  descifrar, si la etiqueta no coincide, **no devuelve nada**: lanza
  `InvalidTag`.

**AES-256** (clave de 32 bytes) frente a AES-128: ambas son seguras hoy;
256 bits da margen frente a futuros avances (incluido Grover en computación
cuántica, que reduciría AES-256 a ~128 bits efectivos).

**Error común:** "cifrar" sin autenticar. Un archivo cifrado con CBC sin
MAC se puede manipular a ciegas; con GCM cualquier cambio se detecta.

## 6. El nonce nunca debe repetirse

*Archivo: `gestor/boveda.py` (`LONGITUD_NONCE`, `cifrar_documento`)*

GCM necesita un **nonce** (*number used once*) de 12 bytes por cada
cifrado. No es secreto (se guarda en la cabecera), pero **jamás puede
repetirse con la misma clave**. Si se repite:

1. GCM genera el mismo flujo de cifrado (modo contador), así que
   `C1 ⊕ C2 = P1 ⊕ P2`: el atacante obtiene el XOR de los dos textos en claro.
   Con un poco de contexto (sabemos que es JSON) se recuperan ambos.
2. Peor aún: con dos mensajes con el mismo nonce se puede despejar la clave
   de autenticación interna (H) y **falsificar** mensajes que pasan la
   verificación. Es el "ataque prohibido" de Joux.

Aquí se genera un nonce **aleatorio nuevo en cada guardado**
(`secrets.token_bytes(12)`). Con 96 bits aleatorios, la probabilidad de
colisión es despreciable mientras se cifren menos de ~2³² mensajes con la
misma clave (NIST SP 800-38D); una bóveda personal guarda unos cientos o
miles de veces. Además `cambiar-maestra` cambia la clave.

Los tests comprueban que 300 guardados seguidos producen 300 nonces
distintos y que el mismo contenido cifrado dos veces da textos distintos.

**Errores comunes:** usar un nonce fijo (`b"\x00" * 12`), un contador que se
reinicia al reabrir el programa, o reutilizar el nonce "porque el contenido
apenas cambió".

## 7. Qué protege el AAD

*Archivo: `gestor/boveda.py` (`aad_de_cabecera`)*

La cabecera (formato, versión, parámetros del KDF, sal, nonce, metadatos)
tiene que ir **en claro**: sin ella no sabríamos cómo derivar la clave. Pero
eso no significa que deba ser **modificable**.

GCM permite pasar **datos asociados (AAD)**: no se cifran, pero entran en la
etiqueta de autenticación. Aquí el AAD es la cabecera serializada de forma
**canónica** (`json.dumps(..., sort_keys=True, separators=(",", ":"))`) para
que los mismos datos den siempre los mismos bytes.

Qué evita:

- **Cambio de versión** (*downgrade*): alguien edita `"version"` o el
  algoritmo para forzar un camino de código más débil. Se detecta.
- **Manipular metadatos**: cambiar la fecha de modificación para esconder una
  restauración de una copia antigua. Los metadatos no influyen en la clave,
  así que **solo** el AAD lo detecta (hay un test específico para esto).
- **Mezclar cabeceras y cuerpos**: pegar el texto cifrado de una bóveda con
  la cabecera de otra.

Si se cambia un byte de la sal o de los parámetros del KDF, la clave
derivada ya es otra y también falla; el AAD cubre además todo lo que **no**
afecta a la clave.

**Error común:** autenticar solo el texto cifrado y confiar en una cabecera
sin proteger ("total, no es secreta").

> Limitación: el AAD no impide un **ataque de reversión** (*rollback*):
> sustituir el archivo por una copia antigua **completa** y válida. Para
> detectarlo habría que guardar en otro sitio un contador o el hash de la
> última versión.

## 8. Errores: InvalidTag sin filtrar datos

*Archivo: `gestor/boveda.py` (`ErrorAutenticacion`)*

Si la maestra es incorrecta **o** el archivo fue manipulado, GCM lanza
`InvalidTag`. El programa lo convierte en un mensaje **único**:

> No se pudo abrir la bóveda: la contraseña maestra es incorrecta o el
> archivo ha sido modificado.

- No distingue los dos casos (GCM tampoco puede, y dar pistas distintas
  ayudaría a un atacante: es el principio del *padding oracle*).
- No muestra traza (`Traceback`), ni datos parciales, ni la excepción
  original (`raise ... from None`).
- **Nunca** se devuelve texto en claro sin verificar: AES-GCM de
  `cryptography` comprueba la etiqueta antes de entregar nada.

Los errores de **formato** (JSON roto, versión desconocida, base64
inválido) sí dan un mensaje específico, porque se detectan antes de usar la
clave y no revelan nada sobre ella.

## 9. `secrets` y no `random`

*Archivos: `gestor/generador.py`, `gestor/kdf.py`, `gestor/boveda.py`*

- `random` usa **Mersenne Twister**: es estadísticamente bueno pero
  **predecible**. Tras observar 624 salidas de 32 bits se reconstruye su
  estado interno y se predicen todas las anteriores y siguientes. Además se
  puede sembrar con la hora.
- `secrets` (y `os.urandom`) usan el **generador criptográfico del sistema
  operativo** (`getrandom()` en Linux, `BCryptGenRandom` en Windows),
  diseñado para que nadie pueda predecir su salida.

Todo lo aleatorio aquí (sal, nonce, contraseñas, frases) usa `secrets`. Un
test comprueba que `generador.py` no importa `random`.

Detalles del generador:

- **Muestreo con rechazo**: para garantizar "al menos una mayúscula, un
  dígito...", se genera una contraseña uniforme y, si no cumple, se descarta
  entera. Forzar "la primera letra mayúscula" reduciría la entropía y crearía
  patrones.
- `secrets.choice` evita el **sesgo de módulo** de `byte % len(alfabeto)`.
- **Frases diceware**: ~870 palabras españolas sin tildes (para teclearlas en
  cualquier teclado) → ~9,8 bits por palabra. 6 palabras ≈ 59 bits, 8 ≈ 78.
  La lista es pública: la seguridad viene de elegir **al azar**, no de que
  la lista sea secreta. (La lista EFF tiene 7 776 palabras, 12,9 bits cada
  una; con una lista más corta hacen falta más palabras.)

## 10. Escritura atómica y permisos 0600

*Archivo: `gestor/boveda.py` (`escribir_atomico`)*

**Error común:** `open(ruta, "w").write(datos)`. Si el programa se cuelga,
se va la luz o el disco se llena a mitad de escritura, el archivo queda
**truncado**: has perdido **todas** tus contraseñas (un archivo cifrado a
medias no se puede descifrar).

Lo que se hace:

1. Crear un temporal **en el mismo directorio** con `tempfile.mkstemp`
   (nombre impredecible, creado con permisos `0600` desde el principio, sin
   ventana en la que otro usuario pueda leerlo).
2. Escribir, `flush()` y `os.fsync()` para que los datos lleguen al disco.
3. `os.replace(temporal, ruta)`: sustitución **atómica** (en POSIX y en
   Windows dentro del mismo volumen). Quien lea el archivo ve la versión
   vieja completa o la nueva completa, nunca una mezcla.
4. `fsync` del directorio para que el cambio de nombre también persista.
5. Si algo falla, se borra el temporal y la versión anterior queda intacta
   (hay un test que simula un fallo de `os.replace`).

**Permisos 0600** (lectura/escritura solo para el propietario): otros
usuarios del sistema no pueden ni copiar el archivo para atacarlo fuera de
línea. En Windows los permisos POSIX tienen efecto limitado.

## 11. La interfaz: getpass, historial y portapapeles

*Archivos: `gestor/cli.py`, `gestor/portapapeles.py`*

- **`getpass`** para la maestra y las contraseñas: sin eco en pantalla.
  **Nunca como argumento**: los argumentos quedan en `~/.bash_history` y son
  visibles para otros usuarios con `ps aux` mientras el proceso corre. Un
  test verifica que ningún comando tiene una opción de ese tipo.
- **`obtener` copia al portapapeles** y lo **limpia** a los 20 s (o al pulsar
  Ctrl+C). `--mostrar` la imprime, pero entonces queda en el *scrollback* de
  la terminal.
- La contraseña se pasa a `xclip`/`wl-copy`/`pbcopy` por la **entrada
  estándar**, no como argumento (de nuevo, `ps`).
- `--notas` sí va como argumento: **no pongas secretos ahí**.
- Al crear la maestra se evalúa su fortaleza y se pide confirmación si es
  débil: es la única barrera contra un ataque fuera de línea.

## 12. El medidor de fortaleza

*Archivo: `gestor/fortaleza.py`*

**Error común:** medir la fortaleza con reglas tipo "8 caracteres, una
mayúscula, un número y un símbolo". `P@ssw0rd1` las cumple y cae en el
primer segundo de cualquier ataque de diccionario.

El medidor (inspirado en `zxcvbn`) estima cuántos intentos necesitaría un
atacante **que conoce los patrones humanos**:

1. Busca patrones y les asigna un coste en bits: contraseñas comunes (por
   rango en la lista), palabras del diccionario, sustituciones *leet*
   (`a→@`, `o→0`), palabras al revés, secuencias (`abc`, `987`),
   repeticiones (`aaa`, `abcabc`), filas y columnas del teclado (`qwerty`,
   `1qaz`), años (19xx/20xx) y fechas.
2. Lo que no encaja en ningún patrón cuenta como fuerza bruta:
   `log2(tamaño del alfabeto)` bits por carácter.
3. Con **programación dinámica** elige la segmentación de **menor** coste
   (la más favorable al atacante).
4. Convierte los bits en puntaje 0–4 (<25, <40, <60, <80, ≥80 bits), da
   tiempos estimados en tres escenarios y consejos en español.

Así `123456` obtiene ~1 bit (es la contraseña más común) y una frase larga
de palabras más de 100. Si `zxcvbn` está instalado se muestra también su
resultado para comparar.

Limitaciones: la lista de contraseñas comunes es **muy corta** (las reales
tienen millones), no conoce tus datos personales (nombre de tu perro) y la
entropía de fuerza bruta **sobreestima** frases con palabras que no están en
la lista. Es una estimación, no una garantía.

## 13. Modelo de amenazas

### Qué SÍ protege

| Amenaza | Defensa |
|---|---|
| Robo del archivo de la bóveda (copia de seguridad, nube, portátil robado) | AES-256-GCM + Argon2id: hay que adivinar la maestra, y cada intento es caro |
| Ataque de diccionario fuera de línea | KDF lento y memory-hard + aviso de maestra débil |
| Tablas precalculadas / atacar varias bóvedas a la vez | Sal aleatoria por bóveda |
| Modificación del archivo (contenido o cabecera) | Etiqueta GCM + AAD → `InvalidTag` |
| Downgrade de versión/algoritmo o parámetros | Cabecera en el AAD + validación estricta |
| Archivo malicioso que pide parámetros enormes | Máximos en los parámetros del KDF |
| Corrupción por cortes durante el guardado | Escritura atómica + `fsync` |
| Otros usuarios del mismo equipo leyendo el archivo | Permisos `0600` |
| Contraseña en el historial del shell o en `ps` | `getpass` y portapapeles por stdin |
| Contraseñas generadas predecibles | `secrets` (CSPRNG del sistema) |
| Revelar qué cuentas tienes | Nombres, usuarios y URLs van cifrados |

### Qué NO protege

- **Keyloggers y malware** en tu equipo: si alguien registra el teclado,
  captura la maestra al escribirla. Ningún gestor puede defenderte de un
  sistema comprometido.
- **Memoria del proceso**: mientras la bóveda está abierta, la clave y las
  contraseñas están en la RAM en claro. Python no permite borrarlas de forma
  fiable (`bytes` y `str` son inmutables, el recolector de basura copia
  objetos, pueden acabar en el *swap* o en un volcado de memoria). Los
  gestores reales usan lenguajes con control de memoria, `mlock`, etc.
- **Portapapeles**: otras aplicaciones (y los historiales de portapapeles de
  algunos escritorios) pueden leerlo mientras dura la copia.
- **Pantalla y terminal**: con `--mostrar` la contraseña queda en el
  *scrollback* y puede verse por encima del hombro o en grabaciones.
- **Maestra débil**: el KDF multiplica el coste, no lo hace infinito.
  `123456` cae igual.
- **Ataques de reversión**: sustituir la bóveda por una copia antigua
  completa y válida no se detecta (ver §7).
- **Metadatos del archivo**: fecha de modificación del sistema de archivos y
  tamaño aproximado del contenido (cuántas entradas hay, a grandes rasgos).
- **Canales laterales** (tiempo, consumo, caché) más allá de lo que ya
  ofrecen las librerías.
- **Acceso concurrente**: dos instancias guardando a la vez pueden pisarse
  (no hay bloqueo de archivo); la última escritura gana.
- **Olvidar la maestra**: no hay recuperación. Sin ella, los datos se
  pierden. Es el precio de que nadie más pueda abrirla.
- **Coacción, phishing o ingeniería social.**

## 14. Tabla resumen de errores evitados

| Decisión | Error común que evita |
|---|---|
| KDF lento (Argon2id) | `sha256(maestra)` como clave: miles de millones de intentos/s |
| Coste en memoria | Ataques masivos con GPU/ASIC |
| Parámetros guardados y validados | Quedarse atascado con parámetros viejos; DoS por parámetros enormes |
| Normalización NFC | Quedarse fuera por escribir "ñ" de otra forma |
| Sal aleatoria de 16 bytes | Rainbow tables; detectar maestras iguales |
| AES-GCM (AEAD) | ECB (patrones visibles); CBC sin MAC (manipulable, *padding oracle*) |
| Nonce aleatorio nuevo por cifrado | Reutilizar nonce → XOR de textos en claro y falsificación |
| Cabecera como AAD | Downgrade, manipulación de metadatos, mezclar cabeceras |
| Mensaje único ante `InvalidTag` | Oráculos de error; filtrar datos en trazas |
| `secrets` | `random` predecible; sesgo de módulo |
| Muestreo con rechazo | Sesgos al forzar posiciones de mayúsculas/números |
| Escritura atómica + `fsync` | Bóveda truncada = todas las contraseñas perdidas |
| Permisos 0600 / `mkstemp` | Otros usuarios copiando la bóveda |
| `getpass`, nada por argumento | Contraseñas en `~/.bash_history` y en `ps` |
| Medidor por patrones | Creer que `P@ssw0rd1` es segura porque "cumple las reglas" |

## Referencias

- RFC 9106 — Argon2 Memory-Hard Function.
- RFC 8018 — PKCS #5 v2.1 (PBKDF2).
- NIST SP 800-38D — Galois/Counter Mode (GCM).
- OWASP Password Storage Cheat Sheet.
- A. Joux, *Authentication Failures in NIST version of GCM* (2006).
- D. Wheeler, *zxcvbn: Low-Budget Password Strength Estimation* (USENIX Security 2016).
- EFF Dice-Generated Passphrases.
