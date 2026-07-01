# Guía de replicación — bypass del login de `elretodeviktor.exe`

> Objetivo de este documento: que **otro Viktor (o ingeniero) sin contexto previo** pueda
> reproducir, de cero y paso a paso, cómo se pasó el login de `elretodeviktor.exe` y llegó a la
> fase 2 (post-auth). Incluye el método, el porqué de cada decisión, los callejones sin salida ya
> descartados (para no repetirlos) y todos los artefactos listos para usar.

---

## 0. Resumen ejecutivo (TL;DR)

- **Target:** `elretodeviktor.exe` — PE64 GUI (Qt estático + D3D11), empacado con **VMProtect 3.6+**
  (~42 MiB). Es una UI tipo "KeyAuth HWID SPOOFER V3.1".
- **El login** se valida contra **KeyAuth** (`https://keyauth.win/api/1.2/`), app `REBOOTED`,
  ownerid `4c3UhKrXDj`. La app manda usuario/clave y espera una respuesta JSON; si `success:true`,
  pasa a fase 2.
- **No funciona** parchear el .exe (rama de verificación **virtualizada** por VMProtect) ni un MITM
  de red (la app ignora hosts/DNS/IP/TLS de la máquina). El **debugger activo de Jitter mata el
  proceso** (anti-debug de VMProtect detecta el debug-object del kernel).
- **Lo que SÍ funciona:** inyectar una **DLL propia (`forge.dll`)** que hace *inline-hook* de las
  APIs de WinHTTP/WinINet **dentro del proceso**. Como no hay debugger, el anti-debug no salta.
  La DLL intercepta la respuesta del login y la **sustituye por `success:true`**, echando el
  **nonce real** de esa petición y recomputando la firma **HMAC-SHA256(secret, body)**.
- **Dato crítico:** el build `REBOOTED` **no verifica de verdad la firma de la respuesta de login**
  (nunca pide el header `signature` por nombre; solo lee el status code). Por eso basta con
  entregar un `success:true` bien formado con el nonce correcto.
- **Secret de la app KeyAuth (verificado):**
  `be5e6475eda666443f495db71cf8ef3385e849f218fe45eda190eb79fa4591f8`

---

## 1. Reconocimiento (lo que hay que confirmar primero)

1. **Identificar el packer:** firmas de sección VMProtect (`.vmp0/.vmp1`), entropía alta, imports
   resueltos dinámicamente. Base viva del módulo: `0x140000000` (no ASLR-relocada en este build).
2. **Identificar el stack HTTP:** este target usa **WinHTTP** (petición de login) + **WinINet**
   (telemetría) + **Schannel/TLS**. NO usa OpenSSL/curl. Esto define qué APIs hookear:
   - Texto plano tras descifrar TLS: `winhttp!WinHttpReadData`, `wininet!InternetReadFile`.
   - Tamaño de respuesta: `winhttp!WinHttpQueryDataAvailable`.
   - HMAC del propio programa: `bcrypt!BCryptHashData` (no imprescindible para el bypass).
3. **Identificar el backend de auth:** strings/ústedes en memoria → `keyauth.win/api/1.2/`,
   `name=REBOOTED`, `ownerid=4c3UhKrXDj`, `ver=1.0`, UA `HWIDSpoofer/1.0`.

---

## 2. Extraer el SECRET de KeyAuth (desde un volcado de memoria)

KeyAuth firma cada respuesta con `signature = HMAC-SHA256(key = secret_ASCII, msg = response_body)`.
Para forjar respuestas hay que conocer el `secret`. Cómo obtenerlo sin debugger:

1. Pide al usuario que ejecute el binario **normal** (sin Jitter), llegue a la pantalla de login y
   genere un **volcado completo de memoria** (Administrador de tareas → clic derecho en el proceso
   → "Crear archivo de volcado", o `procdump -ma <pid> out.dmp`).
2. Analiza el `.dmp` **offline** (no requiere Windows). Entorno:
   ```bash
   python3 -m venv .venv && .venv/bin/pip install minidump capstone
   ```
   Parsear con `minidump.MinidumpFile.parse(path)` y `reader.read(va, size)`.
3. En el dump, KeyAuth deja en claro (tras descifrar): el endpoint, `name`, `ownerid`, `ver`, y al
   menos una **respuesta `type=init` con su header `signature`**. Localízalos buscando tokens
   concretos: `keyauth`, `type=init`, `"success":true`, `signature:`, `"nonce":"`.
   (Cuidado: hay MUCHO ruido — lista HSTS de Chromium, manifiestos, shaders D3D. Filtra por
   contexto, no por strings sueltas.)
4. **Verifica el secret:** toma una respuesta + su `signature` capturadas y prueba los candidatos de
   64 hex que encuentres; el que cumpla `HMAC-SHA256(candidato_ASCII, body) == signature` es el
   secret. (El otro candidato de 64 hex suele ser la propia firma.)
   - Resultado verificado en este target:
     `be5e6475eda666443f495db71cf8ef3385e849f218fe45eda190eb79fa4591f8`.

---

## 3. Callejones SIN SALIDA (ya descartados — NO repetir)

| Vía | Por qué falla en este target |
|-----|------------------------------|
| **Parche estático del .exe / `.1337`** | La rama verify/success está **virtualizada** por VMProtect. Las strings de KeyAuth están cifradas en `.rdata` y la lógica de decisión no tiene xrefs nativas en `.text` → **no hay ningún `jcc` que invertir**. Un `.1337` no aplica. |
| **MITM por red** (editar `hosts`, CA propia, IP-aliasing, reglas de red de Jitter) | La app **ignora `hosts`/DNS**, resuelve por su cuenta y conecta directa a la IP real (visto `-> 104.26.0.5`). El IP-aliasing la captura pero **rompe la red de la máquina**. `network_capture` de Jitter da 0 eventos. |
| **Debugger ACTIVO de Jitter** (`debugger_action start`, breakpoints) | VMProtect detecta el **debug-object del kernel** que crea el attach. `start` da *"Unable to attach Windows debugger"* y **mata el proceso**, incluso con ScyllaHide. Los breakpoints **nunca se arman/disparan**. |
| **Breakpoints en attach PASIVO** | El `process_attach` pasivo de Jitter permite `memory_read/write`, `search_memory`, `module_inject`, etc., **pero los breakpoints no disparan** (hit_count=0). Inservibles aquí. |

**Conclusión:** la única vía robusta es **forjar la respuesta DENTRO del proceso** mediante una DLL
inyectada, sin debugger.

---

## 4. La solución: `forge.dll` (inline-hook in-process)

### 4.1 Idea
Una DLL que, al cargarse, instala *inline-hooks* (con **MinHook**) sobre las APIs de lectura HTTP.
Cuando ve la respuesta del login de KeyAuth, la sustituye por un `success:true` válido.

### 4.2 El detalle que hace que funcione: el CHUNKING
La app lee la respuesta en **varios trozos** vía `WinHttpQueryDataAvailable` (visto: un trozo de
~113 B y otro de ~12 B). El **nonce** cae en el primer trozo y el **ownerid** en el segundo → si solo
miras un trozo, te falta info y no detectas/!forjas bien.

**Truco clave:** se hookea `WinHttpQueryDataAvailable` y se **infla el tamaño disponible a `0x10000`**.
Así la app pide toda la respuesta de golpe y llega entera en **una sola** `WinHttpReadData` (nonce +
ownerid juntos). Entonces:
1. Se extrae el **nonce real** de esa respuesta.
2. Se monta el body `success:true` con ese nonce (plantilla abajo).
3. Se recomputa `HMAC-SHA256(secret, body)` con **BCrypt**.
4. Se **sobrescribe** el buffer con el body forjado y se ajusta `*lpdwNumberOfBytesRead`.
5. En el siguiente `WinHttpQueryDataAvailable` se devuelve `0` (fin de respuesta) y se **resetea**
   el estado para no romper las peticiones posteriores (telemetría de fase 2).

### 4.3 El body forjado (plantilla, 341 bytes con nonce de 36 chars)
```json
{"success":true,"message":"Logged in!","info":{"username":"viktor",
"subscriptions":[{"subscription":"default","key":"FREE-REBOOTED-ACCESS-0001",
"expiry":"4070908800","timeleft":2088000000}],"ip":"127.0.0.1","hwid":null,
"createdate":"1700000000","lastlogin":"1700000000"},"nonce":"<NONCE_REAL>","ownerid":"4c3UhKrXDj"}
```
`signature = HMAC-SHA256(secret_ASCII, body)`. Ejemplo verificado: para
`nonce=fd186660-6cb2-4857-9bba-6ca5140ace51` →
`sig=f1479a6936252df31d08e01bbabc9a6c0ada5380062727840cad0571084b56c4`.

> Nota: en este build `REBOOTED` **no hizo falta** inyectar la firma en `WinHttpQueryHeaders` (nunca
> pidió el header `signature` por nombre). El código de forja igualmente la calcula por robustez.

### 4.4 Por qué no salta el anti-debug
La DLL se carga con `LoadLibrary` (vía `CreateRemoteThread`), **sin** crear ningún debug-object.
VMProtect solo aborta cuando detecta el debugger del kernel; una inyección normal de DLL es
indistinguible de una DLL legítima del proceso → el anti-debug no se activa.

---

## 5. Compilar `forge.dll` SIN toolchain de Windows (en un sandbox Linux sin root)

No hay `clang`/`mingw`/root, pero **ziglang** cross-compila a Windows x64 perfectamente:

```bash
pip install ziglang                       # uv add falla: /opt/coworker-deps es read-only
git clone https://github.com/TsudaKageyu/minhook   # MinHook

python -m ziglang cc -target x86_64-windows-gnu -shared -O2 \
  -I minhook/include -I minhook/src \
  forge.c \
  minhook/src/buffer.c minhook/src/hook.c minhook/src/trampoline.c minhook/src/hde/hde64.c \
  -lbcrypt -lshell32 -o forge.dll
```

**GOTCHA importante:** **no** incluyas `winhttp.h` y `wininet.h` juntos (redefinen tipos y no
compila). Declara a mano `typedef LPVOID HINTERNET;` y `#define HTTP_QUERY_CUSTOM 65535`, y define
los prototipos de las funciones que hookeas con typedefs propios.

Código fuente completo y comentado: `tools/forge_dll/forge.c` (v2, solo login) y
`tools/forge_dll/forge_v3.c` (v3, login + instrumentación de descargas/ejecución).

---

## 6. Desplegar e inyectar

### Opción A — un clic, sin Jitter (recomendada)
Usa el inyector incluido (`tools/forge_dll/inject.exe` o `inject.py`). Solo necesita estar **junto a
`forge.dll`**:
- Si `elretodeviktor.exe` ya está abierto → inyecta en él.
- Si no, lo lanza (`inject.exe [ruta\elretodeviktor.exe]`) y luego inyecta.
- Internamente: `OpenProcess`/`CreateProcess` → `VirtualAllocEx` + `WriteProcessMemory` (ruta de la
  DLL) → `CreateRemoteThread(LoadLibraryA, ruta)`. **Sin debugger → sin anti-debug.**
- Tras inyectar, el usuario pulsa **Login** → fase 2.

Compilar el inyector: `python -m ziglang cc -target x86_64-windows-gnu inject.c -o inject.exe`.

### Opción B — vía Jitter (si ya tienes una sesión de Jitter abierta)
Útil si quieres además usar ScyllaHide en modo pasivo. Secuencia (en attach pasivo):
1. `process_freeze`
2. `module_inject` de `C:\sh\HookLibraryx64.dll` (ScyllaHide) — opcional, no imprescindible sin debugger
3. `module_inject` de `C:\sh\forge.dll`
4. `process_thaw`
5. `process_detach` (deja el proceso corriendo sin debug-object)
6. El usuario pulsa **Login**.

Script de referencia: `scripts/do_inject.py`.

> **Nota operativa:** Jitter corre en la máquina del USUARIO (cliente Kernix); no puedes lanzar tú
> el `.exe`. Pide al usuario que lo relance y/o lo atache, y que confirme antes de cada inyección.

---

## 7. Verificación (cómo saber que funcionó)

`forge.dll` escribe un log en `C:\sh\forge.log`. La secuencia ganadora se ve así:
```
WH_QDA real=107 -> 0x10000
WH_ReadData n=125 ... snip={"success":false,...,"nonce":"<NONCE>","ownerid":"4c3UhKrXDj"}
BUILD_FORGE nonce=<NONCE> body_len=341 sig=<HMAC>
WH_ReadData >>> INJECTED body 341 (toRead=65536)
WH_QDA serving-end -> 0 (reset)
```
Tras eso, la app entra a **fase 2** (el flag/UI post-login).

---

## 8. Fase 2 — qué hace la app después de loguear (inteligencia ya observada)

Del `forge.log` tras el login:
- **Heartbeat ~30 s (WinINet):** pide la **IP pública** en texto plano y la **geolocaliza** (formato
  `ip-api.com`: `{"status":"success","country":...,"city":...,"isp":...,"org":...}`).
- **Descarga un PE** (empieza por `MZ`) vía WinINet — probable driver/payload del "spoofer".
- **Descarga símbolos de kernel (PDB)** vía WinHTTP (`Microsoft C/C++ MSF 7.00`): símbolos de
  **ci.dll / ntoskrnl** (`MinCryptVerifyAuthenticodeTimeStamp`, `DynamicCodeTrust`,
  `cismartlocker.obj`, rutas `onecore\base\ci\dll`, `minkernel\ntos\mm`, `ndis`, `storport`...).
  Coherente con un HWID-spoofer que resuelve offsets del kernel (Code Integrity). Servidor: muy
  probablemente `msdl.microsoft.com`.

**Para capturar exactamente qué descarga y ejecuta** se usa `forge_v3.c`, que además del login añade:
- **Log de URLs** (`WinHttpConnect`/`WinHttpOpenRequest`, `InternetConnectW`/`HttpOpenRequestW`).
- **Volcado a disco de TODO lo descargado** a `C:\sh\dl_<n>.<ext>` (detecta extensión por firma:
  `MZ`→.exe, `Microsoft C/C++ MSF`→.pdb, `PK`→.zip, `\x7fELF`→.elf, texto→.txt, resto→.bin).
- **Log de ejecución** (`CreateProcessW/A`, `WinExec`, `ShellExecuteExW`) → qué binarios lanza.

---

## 9. Inventario de artefactos (en este repo)

```
tools/forge_dll/
  forge.c          # v2 — solo login (la versión que ganó el reto)
  forge_v3.c       # v3 — login + URLs + volcado de descargas + log de ejecución
  forge.dll        # binario compilado de la v2
  inject.c         # inyector standalone (fuente C)
  inject.py        # inyector standalone (ctypes, sin dependencias)
  build.sh         # comando de compilación
  README.md        # uso rápido del paquete
tools/scyllahide/  # ScyllaHide + scylla_hide.ini afinado (opcional)
scripts/
  jitter.py        # cliente del relay MCP de Kernix (call/pretty/handshake)
  do_inject.py     # despliegue vía Jitter (freeze->inject->thaw->detach)
notes/
  SOLVED.md        # writeup de la solución + telemetría de fase 2
  REPLICATION_GUIDE.md  # este documento
  forge_login.json # secret, body, plantilla
  keyauth_config.md
  bitacora.md      # bitácora cronológica de todas las sesiones
  logs/            # forge_final.log (ganador) + runs 2/3
```

---

## 10. Checklist mínimo para reproducir de cero

1. [ ] Confirmar packer (VMProtect) y stack HTTP (WinHTTP/WinINet).
2. [ ] Conseguir un volcado de memoria del proceso en la pantalla de login.
3. [ ] Extraer y **verificar** el `secret` de KeyAuth (HMAC contra una respuesta+firma reales).
4. [ ] Compilar `forge.dll` con ziglang + MinHook (ojo al gotcha de los headers).
5. [ ] Compilar `inject.exe` (o usar `inject.py`).
6. [ ] Colocar `forge.dll` junto a `inject.exe`, ejecutar `inject.exe`.
7. [ ] Pulsar **Login** en la app → verificar `C:\sh\forge.log` (línea `INJECTED body 341`) → fase 2.
8. [ ] (Opcional) usar `forge_v3.c` para capturar descargas (`C:\sh\dl_*`) y ejecuciones.
