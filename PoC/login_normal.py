import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import frida_http as base

LOG = os.path.join(ROOT, "login-normal.log")

def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")

WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

def launch_normal():
    si = base.STARTUPINFO()
    si.cb = ctypes.sizeof(base.STARTUPINFO)
    si.dwFlags = 0x1
    si.wShowWindow = 7  # SW_SHOWMINNOACTIVE
    pi = base.PROCESS_INFORMATION()
    buf = ctypes.create_unicode_buffer(f'"{base.EXE}"')
    os.environ["__COMPAT_LAYER"] = "RunAsInvoker"
    if not base.k.CreateProcessW(None, buf, None, None, False, 0, None,
                                 os.path.dirname(base.EXE), ctypes.byref(si), ctypes.byref(pi)):
        raise ctypes.WinError(ctypes.get_last_error())
    base.k.CloseHandle(pi.hThread)
    return pi.dwProcessId, pi.hProcess

def enum_top():
    out = []
    @WNDENUMPROC
    def cb(h, l):
        out.append(h)
        return True
    base.u.EnumWindows(cb, 0)
    return out

def find_form():
    for h in enum_top():
        if base.cls(h) == "TFormLogin":
            return h
    return None

def click(hwnd):
    base.u.SendMessageW(hwnd, 0x00F5, 0, 0)
    lparam = (10 << 16) | 10
    base.u.SendMessageW(hwnd, 0x0201, 0x0001, lparam)
    base.u.SendMessageW(hwnd, 0x0202, 0, lparam)

def main():
    open(LOG, "w", encoding="utf-8").close()
    pid, hproc = launch_normal()
    log(f"pid {pid} (default desktop)")

    form = None
    for i in range(45):
        time.sleep(1)
        form = find_form()
        if form:
            log(f"login form after {i+1}s hwnd={form}")
            break
    if not form:
        log("login form not found")
        return 1

    # Keep it minimized if possible.
    base.u.ShowWindow(form, 6)  # SW_MINIMIZE

    edits = []
    buttons = []
    for h in base.enum_children(form):
        c = base.cls(h)
        if "TextEdit" in c or c == "TEdit":
            edits.append(h)
        if c == "TcxButton":
            buttons.append(h)

    if len(edits) >= 2:
        user_buf = base.ctypes.create_unicode_buffer("test@example.com")
        pass_buf = base.ctypes.create_unicode_buffer("Test12345!")
        base.u.SendMessageW(edits[0], 0x000C, 0, base.ctypes.cast(user_buf, base.ctypes.c_void_p).value)
        base.u.SendMessageW(edits[1], 0x000C, 0, base.ctypes.cast(pass_buf, base.ctypes.c_void_p).value)
        log("credentials set")

    if buttons:
        log(f"clicking {base.text(buttons[0])!r}")
        click(buttons[0])

    for i in range(15):
        time.sleep(1)
        for h in enum_top():
            if base.cls(h) == "#32770" and base.u.IsWindowVisible(h):
                log(f"dialog {h} title={base.text(h)!r}")
                for ch in base.enum_children(h):
                    log(f"  {base.cls(ch)!r} {base.text(ch)!r}")
                click(h)
                time.sleep(1)

    try:
        base.k.TerminateProcess(hproc, 0)
    except Exception:
        pass
    base.k.CloseHandle(hproc)
    subprocess.run(["powershell", "-NoProfile", "-Command",
        "Get-Process | Where-Object { $_.ProcessName -like '*Unlock*' } | Stop-Process -Force -ErrorAction SilentlyContinue"],
        timeout=30)
    return 0

if __name__ == "__main__":
    sys.exit(main())
