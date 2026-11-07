import ctypes
import ctypes.wintypes as wt
import os
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "pylibs"))
import frida
import frida_http as base

LOG = os.path.join(ROOT, "logs", "bypass_final.log")
GUARD_JS = os.path.join(ROOT, "hook_guard.js")
MODAL_JS = os.path.join(ROOT, "hook_modal.js")
OUTDIR = os.path.join(ROOT, "evidence")

u = base.u
u.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.UINT]
u.GetWindowRect.argtypes = [wt.HWND, ctypes.c_void_p]
u.GetDC.restype = wt.HDC
u.GetDC.argtypes = [wt.HWND]
u.ReleaseDC.argtypes = [wt.HWND, wt.HDC]

gdi = ctypes.WinDLL("gdi32", use_last_error=True)
gdi.CreateCompatibleDC.restype = wt.HDC
gdi.CreateCompatibleDC.argtypes = [wt.HDC]
gdi.CreateCompatibleBitmap.restype = wt.HBITMAP
gdi.CreateCompatibleBitmap.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int]
gdi.SelectObject.restype = wt.HGDIOBJ
gdi.SelectObject.argtypes = [wt.HDC, wt.HGDIOBJ]
gdi.GetDIBits.argtypes = [wt.HDC, wt.HBITMAP, wt.UINT, wt.UINT, ctypes.c_void_p, ctypes.c_void_p, wt.UINT]
gdi.DeleteObject.argtypes = [wt.HGDIOBJ]
gdi.DeleteDC.argtypes = [wt.HDC]
u.PrintWindow.argtypes = [wt.HWND, wt.HDC, wt.UINT]


def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def capture(hwnd, path):
    from PIL import Image

    class RECT(ctypes.Structure):
        _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                    ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

    r = RECT()
    u.GetWindowRect(hwnd, ctypes.byref(r))
    w = max(1, r.right - r.left)
    h = max(1, r.bottom - r.top)
    hdc = u.GetDC(hwnd)
    mdc = gdi.CreateCompatibleDC(hdc)
    bmp = gdi.CreateCompatibleBitmap(hdc, w, h)
    old = gdi.SelectObject(mdc, bmp)
    ok = u.PrintWindow(hwnd, mdc, 2)

    class BIH(ctypes.Structure):
        _fields_ = [("biSize", wt.DWORD), ("biWidth", ctypes.c_long), ("biHeight", ctypes.c_long),
                    ("biPlanes", wt.WORD), ("biBitCount", wt.WORD), ("biCompression", wt.DWORD),
                    ("biSizeImage", wt.DWORD), ("biXPelsPerMeter", ctypes.c_long),
                    ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wt.DWORD), ("biClrImportant", wt.DWORD)]

    bi = BIH()
    bi.biSize = ctypes.sizeof(BIH)
    bi.biWidth = w
    bi.biHeight = -h
    bi.biPlanes = 1
    bi.biBitCount = 32
    bi.biCompression = 0
    buf = ctypes.create_string_buffer(w * h * 4)
    gdi.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bi), 0)
    gdi.SelectObject(mdc, old)
    gdi.DeleteObject(bmp)
    gdi.DeleteDC(mdc)
    u.ReleaseDC(hwnd, hdc)
    img = Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1)
    img.convert("RGB").save(path)
    return ok, w, h


def on_message(message, data):
    if message.get("type") == "error":
        log("FRIDA ERROR " + repr(message))
        return
    if message.get("type") == "send":
        log("FRIDA " + repr(message.get("payload")))


WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
u.EnumWindows.argtypes = [WNDENUMPROC, wt.LPARAM]
u.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
u.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
u.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]


def enum_top():
    out = []

    @WNDENUMPROC
    def cb(h, l):
        out.append(h)
        return True

    u.EnumWindows(cb, 0)
    return out


def dialog_watcher(pid):
    import threading

    def run():
        n = 0
        while True:
            try:
                for h in enum_top():
                    p = wt.DWORD(0)
                    u.GetWindowThreadProcessId(h, ctypes.byref(p))
                    if p.value != pid:
                        continue
                    if base.cls(h) != "#32770":
                        continue
                    u.ShowWindow(h, 0)
                    u.PostMessageW(h, 0x0111, 1, 0)   # WM_COMMAND IDOK
                    u.PostMessageW(h, 0x0010, 0, 0)   # WM_CLOSE
                    n += 1
                    if n <= 30:
                        log(f"dialog killed hwnd={h} text={base.text(h)!r}")
            except Exception as e:
                log(f"dialog watcher error: {e}")
            time.sleep(0.2)

    t = threading.Thread(target=run, daemon=True)
    t.start()


def find(cls):
    for h in enum_top():
        if base.cls(h) == cls:
            return h
    return None


def main():
    open(LOG, "w", encoding="utf-8").close()
    os.makedirs(OUTDIR, exist_ok=True)
    os.environ.pop("__COMPAT_LAYER", None)
    if not ctypes.windll.shell32.IsUserAnAdmin():
        log("WARNING: not elevated")

    pid, hproc = base.launch("", f'"{base.EXE}"', os.path.dirname(base.EXE))
    log(f"pid {pid}")
    dialog_watcher(pid)

    session = None
    for i in range(100):
        try:
            session = frida.attach(pid)
            break
        except Exception:
            time.sleep(0.1)
    if not session:
        log("attach failed")
        return 1

    guard = session.create_script(open(GUARD_JS, encoding="utf-8").read())
    guard.on("message", on_message)
    guard.load()
    log("guard loaded")

    login = None
    for i in range(60):
        time.sleep(1)
        login = find("TFormLogin")
        if login:
            log(f"login form after {i+1}s")
            break
    if not login:
        log("no login form")
        return 1

    time.sleep(1)
    modal = session.create_script(open(MODAL_JS, encoding="utf-8").read())
    modal.on("message", on_message)
    modal.load()
    log("modal loaded")

    proc = mainw = None
    for i in range(40):
        time.sleep(1)
        proc = find("TFormProcessing") or proc
        mainw = find("TUnlockTool") or mainw
        if proc and mainw:
            break
    log(f"processing={proc} main={mainw}")

    if proc:
        u.SetWindowPos(proc, None, -32000, -32000, 380, 520, 0x0010 | 0x0004 | 0x0001)
        log("processing moved off-screen")
    if mainw:
        u.EnableWindow(mainw, True)
        u.ShowWindow(mainw, 5)
        try:
            u.SetForegroundWindow(mainw)
        except Exception:
            pass
        time.sleep(3)
        log(f"main vis={bool(u.IsWindowVisible(mainw))} title={base.text(mainw)!r}")
        path = os.path.join(OUTDIR, "bypass-final.png")
        try:
            ok, w, h = capture(mainw, path)
            log(f"screenshot ok={ok} {w}x{h} -> {path}")
        except Exception as e:
            log(f"screenshot error {e}")

    log("BYPASS ACTIVE - keeping guard alive. Close this console to stop.")
    while True:
        time.sleep(3)
        p = find("TFormProcessing")
        if p and base.u.IsWindowVisible(p):
            u.SetWindowPos(p, None, -32000, -32000, 380, 520, 0x0010 | 0x0004 | 0x0001)
        m = find("TUnlockTool")
        if m and not base.u.IsWindowVisible(m):
            u.ShowWindow(m, 5)


if __name__ == "__main__":
    sys.exit(main())
