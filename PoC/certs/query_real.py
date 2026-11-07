import socket
import ssl

HOST = "vntool.vn"
IPS = ["104.26.14.2", "104.26.15.2", "172.67.75.226"]

REQS = [
    ("GET", "/media/mtk_emi.txt"),
    ("GET", "/media/exy_set.txt"),
    ("GET", "/apiv4r21/update/?format=json&tool_name__name__iexact=UnlockTool"),
    ("GET", "/apiv4r21/current_time/"),
]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

for method, path in REQS:
    done = False
    for ip in IPS:
        try:
            s = socket.create_connection((ip, 443), timeout=15)
            ss = ctx.wrap_socket(s, server_hostname=HOST)
            req = (f"{method} {path} HTTP/1.1\r\n"
                   f"Host: {HOST}\r\n"
                   f"Accept: */*\r\n"
                   f"Accept-Encoding: identity\r\n"
                   f"User-Agent: UnlockTool\r\n"
                   f"Connection: close\r\n\r\n").encode()
            ss.sendall(req)
            data = b""
            while True:
                try:
                    b = ss.recv(8192)
                except Exception:
                    break
                if not b:
                    break
                data += b
            ss.close()
            print("=" * 25, path, "via", ip)
            print(data[:2000].decode("latin1", "replace"))
            print()
            done = True
            break
        except Exception as e:
            print("!!", ip, type(e).__name__, e)
    if not done:
        print("FAILED", path)
