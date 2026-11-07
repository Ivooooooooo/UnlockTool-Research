function bt(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 18).map(function (a) {
      const m = Process.findModuleByAddress(a);
      return m ? (m.name + "+0x" + a.sub(m.base).toString(16)) : a.toString();
    });
  } catch (e) { return []; }
}

const SERIAL_RE = /serial number|requires valid serial|valid serial/i;
let boxCount = 0;

function hookBox(modName, fnName, wide) {
  try {
    const p = Process.getModuleByName(modName).getExportByName(fnName);
    if (!p) return;
    const orig = new NativeFunction(p, "int", ["pointer", "pointer", "pointer", "uint32"], "stdcall");
    const cb = new NativeCallback(function (hwnd, text, caption, type) {
      let t = null, c = null;
      try {
        t = wide ? text.readUtf16String(2048) : text.readUtf8String(2048);
        c = wide ? caption.readUtf16String(512) : caption.readUtf8String(512);
      } catch (e) {}
      if (boxCount < 60) {
        boxCount++;
        send({ guardBoxSuppressed: fnName, text: t, caption: c });
      }
      // suppress every message box
      return 1; // IDOK
    }, "int", ["pointer", "pointer", "pointer", "uint32"]);
    Interceptor.replace(p, cb);
    send({ replaced: fnName });
  } catch (e) { send({ boxErr: fnName, e: String(e) }); }
}

hookBox("user32.dll", "MessageBoxW", true);
hookBox("user32.dll", "MessageBoxA", false);
hookBox("user32.dll", "MessageBoxExW", true);
hookBox("user32.dll", "MessageBoxExA", false);

function replaceReturn(modName, fnName, ret, argc) {
  try {
    const m = Process.findModuleByName(modName);
    if (!m) return;
    const p = m.getExportByName(fnName);
    if (!p) { send({ noExportGuard: fnName }); return; }
    const argTypes = [];
    for (let i = 0; i < argc; i++) argTypes.push("pointer");
    Interceptor.replace(p, new NativeCallback(function () {
      send({ guardSuppressed: fnName });
      return ret;
    }, "int", argTypes));
    send({ replacedGuard: fnName });
  } catch (e) { send({ guardErr: fnName, e: String(e) }); }
}

replaceReturn("user32.dll", "MessageBoxIndirectW", 1, 1);
replaceReturn("user32.dll", "MessageBoxIndirectA", 1, 1);
replaceReturn("user32.dll", "MessageBoxTimeoutW", 1, 6);
replaceReturn("user32.dll", "MessageBoxTimeoutA", 1, 6);
replaceReturn("shlwapi.dll", "SHMessageBoxCheckW", 1, 6);
replaceReturn("shlwapi.dll", "SHMessageBoxCheckA", 1, 6);
replaceReturn("user32.dll", "DialogBoxParamW", 1, 5);
replaceReturn("user32.dll", "DialogBoxParamA", 1, 5);
replaceReturn("user32.dll", "DialogBoxIndirectParamW", 1, 5);
replaceReturn("user32.dll", "DialogBoxIndirectParamA", 1, 5);

// catch any #32770 dialog that still gets created: hide it and post IDOK
try {
  const u32 = Process.getModuleByName("user32.dll");
  const GetClassNameW = new NativeFunction(u32.getExportByName("GetClassNameW"), "int", ["pointer", "pointer", "int"], "stdcall");
  const ShowWindowF = new NativeFunction(u32.getExportByName("ShowWindow"), "int", ["pointer", "int"], "stdcall");
  const PostMessageW = new NativeFunction(u32.getExportByName("PostMessageW"), "int", ["pointer", "uint", "pointer", "pointer"], "stdcall");
  Interceptor.attach(u32.getExportByName("CreateWindowExW"), {
    onLeave(ret) {
      if (ret.isNull()) return;
      try {
        const buf = Memory.alloc(128);
        GetClassNameW(ret, buf, 64);
        const cls = buf.readUtf16String();
        if (cls === "#32770") {
          send({ guardDialog: cls });
          ShowWindowF(ret, 0);
          PostMessageW(ret, 0x0111, ptr(1), ptr(0)); // WM_COMMAND IDOK
          PostMessageW(ret, 0x0010, ptr(0), ptr(0)); // WM_CLOSE
        }
      } catch (e) {}
    }
  });
  send({ guardDialogHook: true });
} catch (e) { send({ guardDialogErr: String(e) }); }

function replaceExit(modName, fnName, returnValue) {
  try {
    const p = Process.getModuleByName(modName).getExportByName(fnName);
    if (!p) { send({ noExport: fnName }); return; }
    const cb = new NativeCallback(function (a, b) {
      send({ blockedExit: fnName, a: a.toString(), b: b.toString(), bt: bt(null) });
      if (returnValue !== null) return returnValue;
      while (true) {}
    }, returnValue === null ? "void" : "int", ["pointer", "pointer"]);
    Interceptor.replace(p, cb);
    send({ replacedExit: fnName });
  } catch (e) { send({ exitErr: fnName, e: String(e) }); }
}

replaceExit("kernel32.dll", "ExitProcess", null);
replaceExit("kernel32.dll", "TerminateProcess", 1);
replaceExit("ntdll.dll", "RtlExitUserProcess", null);
try {
  const p = Process.getModuleByName("ntdll.dll").getExportByName("NtTerminateProcess");
  if (p) {
    const cb = new NativeCallback(function () {
      send({ blockedExit: "NtTerminateProcess" });
      return 0;
    }, "int", ["pointer", "pointer"]);
    Interceptor.replace(p, cb);
    send({ replacedExit: "NtTerminateProcess" });
  }
} catch (e) {}

send({ guardInstalled: true });
