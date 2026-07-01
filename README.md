# forge.dll — bypass del login de elretodeviktor.exe (sin Jitter)

DLL in-process que intercepta la respuesta del login KeyAuth y la sustituye por `success:true`
(echando el nonce real y recomputando HMAC-SHA256). Sin debugger -> sin anti-debug de VMProtect.
Detalle completo del método en `notes/REPLICATION_GUIDE.md`.

## Archivos
- `forge.dll`       binario v2 (solo login) — la versión que ganó el reto.
- `forge_v3.dll`    v3.1 = login + log de URLs + VUELCA TODO lo que descarga a `C:\sh\dl_*` + log de
                    ejecución (CreateProcess/WinExec/ShellExecute). Renómbrala a `forge.dll` para usarla.
                    v3.1 (Sesión 14) ARREGLA el bug de la v3: distingue login vs init por la PETICIÓN
                    (`type=login` via WinHttpSendRequest/WriteData) y NUNCA inyecta sobre el `init`,
                    así la app conserva el `sessionid` real y el spoofer procede a descargar/ejecutar.
                    v3.2 (Sesión 15) añade hooks WinINet InternetOpenUrlW/A (loguea la URL del payload)
                    e InternetCloseHandle, y separa los dumps por petición (1 fichero/descarga) para que
                    el PE no salga concatenado con el ruido de ip-api en handles keep-alive.
- `inject.exe`      inyector de un clic (lanza/atacha el target e inyecta la DLL de al lado).
- `inject.py`       mismo inyector en Python (ctypes, sin dependencias).
- `forge.c` / `forge_v3.c` / `inject.c`   fuentes.
- `build.sh`        comandos de compilación (ziglang + MinHook).

## Uso rápido (un clic, recomendado)
1. Pon `inject.exe` y `forge.dll` (o `forge_v3.dll` renombrada a `forge.dll`) EN LA MISMA CARPETA.
   Para capturar lo que descarga/ejecuta usa la v3:  `copy forge_v3.dll forge.dll`
2. (Opcional) deja `inject.exe` junto a `elretodeviktor.exe`, o pásale la ruta:
   `inject.exe "C:\ruta\elretodeviktor.exe"`
3. Doble clic en `inject.exe`  (clic derecho -> Ejecutar como administrador si pide permisos).
   - Si el juego/app ya está abierto, lo detecta e inyecta directamente.
4. Pulsa **Login** en la app -> entra a fase 2.
5. Revisa `C:\sh\forge.log` (debe aparecer `INJECTED body 341`). Con la v3, lo descargado queda en
   `C:\sh\dl_*` y lo que ejecuta en el log (`EXEC ...`).

## Uso con Python (alternativa)
`python inject.py`   (o `python inject.py "C:\ruta\elretodeviktor.exe"`)

## Notas
- La DLL crea `C:\sh\` sola si no existe (ahí van log y volcados).
- 64-bit. `forge.dll` debe ser x64 (lo es). Ejecuta como administrador si OpenProcess falla.
- Si no detecta el login: asegúrate de inyectar ANTES de pulsar Login (la v3 fuerza la carga de
  winhttp/wininet, así que vale inyectar nada más arrancar).
