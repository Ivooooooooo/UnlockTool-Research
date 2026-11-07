import datetime
import json
import os
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CHAIN = os.path.join(HERE, "server_chain.pem")
KEY = os.path.join(HERE, "server_key.pem")
LOG = os.path.join(HERE, "requests.log")
BODYDIR = os.path.join(HERE, "bodies")
RESPONSE_FILE = os.path.join(HERE, "response.json")
os.makedirs(BODYDIR, exist_ok=True)

_lock = threading.Lock()

ORIGINS = {
    "vntool.vn": ("104.26.14.2", "vntool.vn"),
    "mtk.unlocktool.net": ("103.155.161.42", "mtk.unlocktool.net"),
    "bypass.vntools.net": ("103.155.161.42", "bypass.vntools.net"),
    "ut-data.vntool.net": ("185.183.33.65", "ut-data.vntool.net"),
}

MEDIA = {
    "/media/mtk_emi.txt": "https://mtk.unlocktool.net/uploads/MTK_EMI",
    "/media/exy_set.txt": "https://mtk.unlocktool.net/uploads/EXY_SET",
}

CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def log(line):
    with _lock:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    print(line, flush=True)


def override(path):
    try:
        with open(RESPONSE_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return None
    for prefix, spec in cfg.items():
        if path.startswith(prefix):
            if isinstance(spec, dict) and "file" in spec:
                with open(os.path.join(HERE, spec["file"]), "rb") as f:
                    return int(spec.get("status", 200)), spec.get("type", "application/json"), f.read()
            if isinstance(spec, dict) and "json" in spec:
                return int(spec.get("status", 200)), "application/json", json.dumps(spec["json"]).encode()
            if isinstance(spec, str):
                return 200, "application/json", spec.encode()
    return None


def proxy(host, method, path, headers, body):
    ip, sni = ORIGINS[host]
    s = socket.create_connection((ip, 443), timeout=25)
    ss = CTX.wrap_socket(s, server_hostname=sni)
    hdrs = []
    for k, v in headers.items():
        if k.lower() in ("connection", "proxy-connection", "content-length", "host"):
            continue
        hdrs.append((k, v))
    hdrs.append(("Host", sni))
    hdrs.append(("Connection", "close"))
    if body:
        hdrs.append(("Content-Length", str(len(body))))
    req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs) + "\r\n"
    ss.sendall(req.encode("latin1") + body)
    data = b""
    while True:
        b = ss.recv(65536)
        if not b:
            break
        data += b
    ss.close()
    return data


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        body = self.rfile.read(length) if length else b""
        path = self.path
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        stamp = datetime.datetime.now().strftime("%H%M%S%f")
        log(f"{datetime.datetime.now().isoformat()} {self.command} {path} host={host} len={length}")
        for k, v in self.headers.items():
            log(f"    H {k}: {v}")
        if body:
            with open(os.path.join(BODYDIR, f"{stamp}_{self.command}.bin"), "wb") as f:
                f.write(body)
            log("    BODY " + body.decode("utf-8", "replace")[:4000])

        # 1) explicit overrides
        ov = override(path)
        if ov:
            status, ctype, payload = ov
            log(f"    override -> {status} {ctype} {len(payload)}")
            self._send(status, ctype, payload)
            return

        # 2) media endpoint -> real URL text
        if path in MEDIA:
            payload = MEDIA[path].encode()
            log(f"    media -> {len(payload)}")
            self._send(200, "text/plain; charset=utf-8", payload)
            return

        # 3) proxy to real origin
        if host in ORIGINS:
            try:
                raw = proxy(host, self.command, path, self.headers, body)
                head, sep, rest = raw.partition(b"\r\n\r\n")
                try:
                    first = head.split(b"\r\n", 1)[0].decode("latin1")
                    code = int(first.split(" ")[1])
                except Exception:
                    code = 200
                ctype = "application/octet-stream"
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-type:"):
                        ctype = line.split(b":", 1)[1].strip().decode("latin1")
                with open(os.path.join(BODYDIR, f"{stamp}_RESP.bin"), "wb") as f:
                    f.write(raw)
                log(f"    proxied -> {code} {ctype} total={len(raw)} body={len(rest)}")
                if rest:
                    try:
                        log("    RESP " + rest[:4000].decode("utf-8", "replace").replace("\r", "\\r").replace("\n", "\\n"))
                    except Exception:
                        pass
                self._send_raw(raw)
                return
            except Exception as e:
                log(f"    proxy error: {type(e).__name__}: {e}")
                self._send(502, "application/json", b"{}")
                return

        # 4) fallback
        self._send(200, "application/json", b"{}")

    def _send(self, status, ctype, payload):
        keep = "close" not in (self.headers.get("Connection") or "").lower()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "keep-alive" if keep else "close")
        self.end_headers()
        self.wfile.write(payload)

    def _send_raw(self, raw):
        self.wfile.write(raw)
        self.close_connection = True

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle

    def log_message(self, fmt, *args):
        pass


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CHAIN, KEY)
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    except Exception:
        pass
    httpd = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    log(f"relay listening on 443, log={LOG}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
