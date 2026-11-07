import json
import os
import urllib.request

URL = "https://discord.com/api/webhooks/1402471015400997018/tZ34rso16BsGIlhbEB-rCdCZyWFyklPyz5wH2M0L_v9eXONi9LRgJ22CQ8VRGoAW4g-K"
IMG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence", "bypass-final.png")

content = (
    "✅ **UnlockTool 2026.11.05.0 — Local UI bypass OK**\n"
    "La ventana principal se abre **sin cuenta ni licencia** mediante bypass en runtime (Frida):\n"
    "• `TFormLogin.ModalResult` forzado a `mrOk` (`Self+0x2FC`)\n"
    "• Guard de WinLicense/Themida: bloqueo de `ExitProcess`/`TerminateProcess` y supresión del mensaje de serial\n"
    "• `TFormProcessing` movido fuera de pantalla y `TUnlockTool` mostrada\n"
    "El login contra el servidor sigue requiriendo credenciales válidas.\n"
    "Evidencia adjunta: ventana principal completa (1453×915)."
)

with open(IMG, "rb") as f:
    img = f.read()

boundary = "----UnlockToolREBoundary"
payload = json.dumps({"content": content})

body = bytearray()
body += f"--{boundary}\r\n".encode()
body += b'Content-Disposition: form-data; name="payload_json"\r\n'
body += b"Content-Type: application/json\r\n\r\n"
body += payload.encode() + b"\r\n"
body += f"--{boundary}\r\n".encode()
body += b'Content-Disposition: form-data; name="file"; filename="bypass-final.png"\r\n'
body += b"Content-Type: image/png\r\n\r\n"
body += img + b"\r\n"
body += f"--{boundary}--\r\n".encode()

req = urllib.request.Request(URL, data=bytes(body), method="POST")
req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print("status", r.status)
        print(r.read().decode("utf-8", "replace")[:500])
except urllib.error.HTTPError as e:
    print("HTTP", e.code)
    print(e.read().decode("utf-8", "replace")[:1000])
