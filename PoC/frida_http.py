import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "pylibs"))
sys.path.insert(0, ROOT)
import frida

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

u = ctypes.WinDLL("user32", use_last_error=True)
k = ctypes.WinDLL("kernel32", use_last_error=True)

u.CreateDesktopW.restype = wt.HANDLE
u.CreateDesktopW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.c_void_p]
u.CloseDesktop.argtypes = [wt.HANDLE]
u.EnumDesktopWindows.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.LPARAM]
u.EnumChildWindows.argtypes = [wt.HWND, ctypes.c_void_p, wt.LPARAM]
u.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
u.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
u.SendMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
u.SendMessageW.restype = wt.LPARAM
u.IsWindowVisible.argtypes = [wt.HWND]

k.CreateProcessW.restype = wt.BOOL
k.CreateProcessW.argtypes = [wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wt.BOOL,
                             wt.DWORD, ctypes.c_void_p, wt.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p]
k.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
k.CloseHandle.argtypes = [wt.HANDLE]

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR), ("lpTitle", wt.LPWSTR),
        ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
        ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
        ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
        ("lpReserved2", ctypes.c_void_p), ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE),
        ("hStdError", wt.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]

WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

EXE = os.path.join(ROOT, "..", "Binaries", "UnlockTool-2026-11-05-0.packed.exe")
LOG = os.path.join(ROOT, "logs", "frida-http.log")
DESK = f"UTFR{os.getpid() % 10000}"

def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def launch(desktop, cmdline, cwd):
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    si.lpDesktop = desktop
    si.dwFlags = 0x1
    si.wShowWindow = 1
    pi = PROCESS_INFORMATION()
    buf = ctypes.create_unicode_buffer(cmdline)
    if not k.CreateProcessW(None, buf, None, None, False, 0, None, cwd, ctypes.byref(si), ctypes.byref(pi)):
        raise ctypes.WinError(ctypes.get_last_error())
    k.CloseHandle(pi.hThread)
    return pi.dwProcessId, pi.hProcess

def text(hwnd, n=512):
    b = ctypes.create_unicode_buffer(n)
    u.GetWindowTextW(hwnd, b, n)
    return b.value

def cls(hwnd, n=256):
    b = ctypes.create_unicode_buffer(n)
    u.GetClassNameW(hwnd, b, n)
    return b.value

def enum_desktop(hdesk):
    out = []
    @WNDENUMPROC
    def cb(hwnd, lparam):
        out.append(hwnd)
        return True
    u.EnumDesktopWindows(hdesk, cb, 0)
    return out

def enum_children(hwnd):
    out = []
    @WNDENUMPROC
    def cb(h, lparam):
        out.append(h)
        return True
    u.EnumChildWindows(hwnd, cb, 0)
    return out

def find_login(hdesk):
    for h in enum_desktop(hdesk):
        if cls(h) == "TFormLogin":
            return h
    return None

JS = r"""
function tryStr(p) {
  try {
    if (p.isNull()) return null;
    const s = p.readUtf8String(512);
    if (!s) return null;
    if (/^[\x20-\x7e\r\n\t]{2,}$/.test(s)) return s;
  } catch (e) {}
  return null;
}

function hookModule(name, prefixes) {
  let mod;
  try { mod = Process.getModuleByName(name); } catch (e) { send({error: "no module " + name}); return; }
  let n = 0;
  const ex = mod.enumerateExports();
  for (const e of ex) {
    let ok = false;
    for (const p of prefixes) { if (e.name.indexOf(p) === 0) { ok = true; break; } }
    if (!ok) continue;
    try {
      Interceptor.attach(e.address, {
        onEnter(args) {
          const a = [];
          for (let i = 0; i < 6; i++) {
            const s = tryStr(args[i]);
            if (s) a.push(i + ":" + s);
          }
          send({mod: name, fn: e.name, args: a});
        },
        onLeave(retval) {
          const s = tryStr(retval);
          if (s) send({mod: name, fn: e.name, ret: s});
        }
      });
      n++;
    } catch (err) {}
  }
  send({mod: name, hooked: n});
}

function hookWinHttp() {
  const m = Process.findModuleByName("winhttp.dll");
  if (!m) { send({error: "no winhttp"}); return; }
  function attach(name, handlers) {
    const p = m.findExportByName(name);
    if (!p) { send({missingWinHttp: name}); return; }
    try { Interceptor.attach(p, handlers); send({hookedWinHttp: name}); }
    catch (e) { send({errWinHttp: name, e: String(e)}); }
  }
  attach("WinHttpOpen", { onEnter(args) {
    try { send({fn: "WinHttpOpen", agent: args[0].isNull() ? null : args[0].readUtf16String(), access: args[1].toInt32(), proxy: args[2].isNull() ? null : args[2].readUtf16String()}); } catch (e) {}
  }});
  attach("WinHttpConnect", { onEnter(args) {
    try { send({fn: "WinHttpConnect", server: args[1].isNull() ? null : args[1].readUtf16String(), port: args[2].toInt32()}); } catch (e) {}
  }});
  attach("WinHttpOpenRequest", { onEnter(args) {
    try { send({fn: "WinHttpOpenRequest", verb: args[1].isNull() ? null : args[1].readUtf16String(), path: args[2].isNull() ? null : args[2].readUtf16String()}); } catch (e) {}
  }});
  attach("WinHttpSendRequest", { onEnter(args) {
    try {
      const hl = args[2].toInt32();
      const bl = args[4].toInt32();
      const o = {fn: "WinHttpSendRequest", headersLen: hl, bodyLen: bl};
      if (hl > 0 && !args[1].isNull()) o.headers = args[1].readUtf16String(hl);
      if (bl > 0 && !args[3].isNull()) o.body = args[3].readUtf8String(Math.min(bl, 8192));
      send(o);
    } catch (e) { send({fn: "WinHttpSendRequest", err: String(e)}); }
  }});
  attach("WinHttpReceiveResponse", { onLeave(ret) {
    send({fn: "WinHttpReceiveResponse", ret: ret.toInt32()});
  }});
  attach("WinHttpReadData", {
    onEnter(args) { this.buf = args[1]; this.out = args[3]; },
    onLeave(ret) {
      try {
        const n = this.out.isNull() ? 0 : this.out.readU32();
        if (n > 0) send({fn: "WinHttpReadData", len: n, data: this.buf.readUtf8String(Math.min(n, 8192))});
      } catch (e) {}
    }
  });
}

setTimeout(function () {
  const mods = Process.enumerateModules();
  send({modules: mods.map(function (m) { return m.name; }).filter(function (n) {
    return /ssl|crypto|eay|http|socket|curl|winhttp|secur32|bcrypt/i.test(n);
  })});

  function hookSsl(name) {
    const m = Process.findModuleByName(name);
    if (!m) return;
    ["SSL_write", "SSL_read"].forEach(function (fn) {
      const p = m.findExportByName(fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter(args) {
            if (fn === "SSL_write") {
              const len = args[2].toInt32();
              if (len > 0 && len < 65536) {
                try { send({fn: fn, len: len, data: args[1].readUtf8String(Math.min(len, 8192))}); } catch (e) {}
              }
            } else {
              this.buf = args[1];
              this.len = args[2].toInt32();
            }
          },
          onLeave(ret) {
            if (fn === "SSL_read" && ret.toInt32() > 0) {
              try { send({fn: fn, len: ret.toInt32(), data: this.buf.readUtf8String(Math.min(ret.toInt32(), 8192))}); } catch (e) {}
            }
          }
        });
        send({hookedSsl: name + "!" + fn});
      } catch (e) {}
    });
  }

  ["libssl-1_1.dll", "libssl-3.dll", "ssleay32.dll", "libssl.dll"].forEach(hookSsl);

  const ws = Process.findModuleByName("ws2_32.dll");
  if (ws) {
    ["send", "recv"].forEach(function (fn) {
      const p = ws.findExportByName(fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter(args) {
            if (fn === "send") {
              const len = args[2].toInt32();
              if (len > 0 && len < 4096) {
                try { send({fn: "ws2_send", len: len, data: args[1].readUtf8String(Math.min(len, 512))}); } catch (e) {}
              }
            }
          }
        });
        send({hookedWs: fn});
      } catch (e) {}
    });
  }

  hookWinHttp();
  hookModule("unlocktool2.dll", ["CkSocket_", "CkHttp_", "CkRest_"]);

  const seen = {};
  function pollMods() {
    Process.enumerateModules().forEach(function (m) {
      if (seen[m.name]) return;
      seen[m.name] = true;
      if (/ssl|crypto|eay|gnutls|mbedtls/i.test(m.name)) {
        send({newModule: m.name, base: m.base.toString()});
        hookSsl(m.name);
      }
    });
  }
  setInterval(pollMods, 500);
  pollMods();

  const ws2 = Process.findModuleByName("ws2_32.dll");
  if (ws2) {
    ["WSASend", "WSARecv", "send", "recv", "connect"].forEach(function (fn) {
      const p = ws2.findExportByName(fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter(args) {
            try {
              if (fn === "WSASend") {
                const len = args[1].readU32();
                const buf = args[1].add(4).readPointer();
                if (len > 0 && len < 8192) send({fn: "WSASend", len: len, data: buf.readUtf8String(Math.min(len, 512))});
              } else if (fn === "send") {
                const len = args[2].toInt32();
                if (len > 0 && len < 8192) send({fn: "send", len: len, data: args[1].readUtf8String(Math.min(len, 512))});
              } else if (fn === "connect") {
                const sa = args[1];
                const family = sa.readU16();
                const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                let ip = "";
                if (family === 2) {
                  const b = new Uint8Array(sa.add(4).readByteArray(4));
                  ip = b[0] + "." + b[1] + "." + b[2] + "." + b[3];
                }
                send({fn: "connect", family: family, ip: ip, port: port});
              }
            } catch (e) {}
          }
        });
        send({hookedWs2: fn});
      } catch (e) {}
    });
  }
}, 100);
"""

def main():
    open(LOG, "w", encoding="utf-8").close()
    hdesk = u.CreateDesktopW(DESK, None, None, 0, 0x000F01FF, None)
    if not hdesk:
        log(f"CreateDesktop failed {ctypes.get_last_error()}")
        return 1
    os.environ["__COMPAT_LAYER"] = "RunAsInvoker"
    pid, hproc = launch(DESK, f'"{EXE}"', os.path.dirname(EXE))
    log(f"pid {pid} desktop {DESK}")

    form = None
    for i in range(45):
        time.sleep(1)
        form = find_login(hdesk)
        if form:
            log(f"login form after {i+1}s hwnd={form}")
            break
    if not form:
        log("login form not found")
        return 1

    session = frida.attach(pid)
    script = session.create_script(JS)

    def on_message(message, data):
        if message.get("type") == "send":
            log("FRIDA " + repr(message.get("payload")))
        elif message.get("type") == "error":
            log("FRIDA ERROR " + repr(message))

    script.on("message", on_message)
    script.load()
    log("frida loaded")
    time.sleep(1)

    edits = []
    buttons = []
    for h in enum_children(form):
        c = cls(h)
        if "TextEdit" in c or c == "TEdit":
            edits.append(h)
        if c == "TcxButton":
            buttons.append(h)

    if len(edits) >= 2:
        user_buf = ctypes.create_unicode_buffer("test@example.com")
        pass_buf = ctypes.create_unicode_buffer("Test12345!")
        u.SendMessageW(edits[0], 0x000C, 0, ctypes.cast(user_buf, ctypes.c_void_p).value)
        u.SendMessageW(edits[1], 0x000C, 0, ctypes.cast(pass_buf, ctypes.c_void_p).value)
        log("credentials set")

    if buttons:
        btn = buttons[0]
        log(f"clicking {text(btn)!r}")
        u.SendMessageW(btn, 0x00F5, 0, 0)
        lparam = (10 << 16) | 10
        u.SendMessageW(btn, 0x0201, 0x0001, lparam)
        u.SendMessageW(btn, 0x0202, 0, lparam)

    for i in range(30):
        time.sleep(1)
        tcp = subprocess.run(["powershell", "-NoProfile", "-Command",
            f"Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {{ $_.OwningProcess -eq {pid} }} | Select-Object State,RemoteAddress,RemotePort | Format-Table -AutoSize | Out-String"],
            capture_output=True, text=True, timeout=30).stdout
        if tcp.strip():
            log(f"tcp t={i+1}:\n{tcp.strip()}")

    try:
        session.detach()
    except Exception:
        pass
    try:
        k.TerminateProcess(hproc, 0)
    except Exception:
        pass
    k.CloseHandle(hproc)
    subprocess.run(["powershell", "-NoProfile", "-Command",
        "Get-Process | Where-Object { $_.ProcessName -like '*Unlock*' } | Stop-Process -Force -ErrorAction SilentlyContinue"],
        timeout=30)
    u.CloseDesktop(hdesk)
    return 0

if __name__ == "__main__":
    sys.exit(main())
