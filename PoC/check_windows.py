import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import frida_http as base

u = base.u
WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
u.EnumWindows.argtypes = [WNDENUMPROC, wt.LPARAM]
u.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]


def enum():
    out = []

    @WNDENUMPROC
    def cb(h, l):
        out.append(h)
        return True

    u.EnumWindows(cb, 0)
    return out


ps = subprocess.run(["powershell", "-NoProfile", "-Command",
    "Get-Process | Where-Object { $_.ProcessName -like '*Unlock*' } | Select-Object -ExpandProperty Id"],
    capture_output=True, text=True)
pids = set(int(x) for x in ps.stdout.split() if x.strip().isdigit())
print("pids", pids)
for h in enum():
    p = wt.DWORD(0)
    u.GetWindowThreadProcessId(h, ctypes.byref(p))
    if p.value not in pids:
        continue
    c = base.cls(h)
    t = base.text(h)
    if c in ("#32770", "TUnlockTool", "TFormProcessing", "TFormLogin") or c.startswith("TForm"):
        print(f"hwnd={h} cls={c!r} text={t!r} vis={bool(u.IsWindowVisible(h))} enabled={bool(u.IsWindowEnabled(h))}")
