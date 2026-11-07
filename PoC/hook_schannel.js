let hooked = false;

function emit(label, ptr, len) {
  if (!ptr || len <= 0) return;
  try {
    const n = Math.min(len, 65536);
    const bytes = ptr.readByteArray(n);
    const u = new Uint8Array(bytes);
    let txt = "";
    for (let i = 0; i < n; i++) {
      const c = u[i];
      txt += ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) ? String.fromCharCode(c) : ".";
    }
    send({label: label, len: len, text: txt.slice(0, 2000)}, bytes);
  } catch (e) {}
}

function hookSspi() {
  if (hooked) return;
  const m = Process.findModuleByName("sspicli.dll");
  if (!m) return;
  for (const fn of ["EncryptMessage", "DecryptMessage"]) {
    let p = null;
    try {
      p = (typeof m.getExportByName === "function") ? m.getExportByName(fn) : m.findExportByName(fn);
    } catch (e) { p = null; }
    if (!p) continue;
    try {
      Interceptor.attach(p, {
        onEnter(args) {
          try {
            const desc = (fn === "EncryptMessage") ? args[2] : args[1];
            const cBuffers = desc.add(4).readU32();
            const pBuffers = desc.add(8).readPointer();
            if (fn === "EncryptMessage") {
              for (let i = 0; i < cBuffers; i++) {
                const b = pBuffers.add(i * 12);
                const cb = b.readU32();
                const type = b.add(4).readU32();
                const pv = b.add(8).readPointer();
                if (type === 1 && cb > 0) emit("ENC", pv, cb);
              }
            } else {
              this.pBuffers = pBuffers;
              this.cBuffers = cBuffers;
            }
          } catch (e) {}
        },
        onLeave(ret) {
          if (fn === "DecryptMessage" && this.pBuffers) {
            try {
              for (let i = 0; i < this.cBuffers; i++) {
                const b = this.pBuffers.add(i * 12);
                const cb = b.readU32();
                const type = b.add(4).readU32();
                const pv = b.add(8).readPointer();
                if (type === 1 && cb > 0) emit("DEC", pv, cb);
              }
            } catch (e) {}
          }
        }
      });
      send({hookedSspi: fn});
    } catch (e) {
      send({errSspi: fn, e: String(e)});
    }
  }
  hooked = true;
}

hookSspi();
setInterval(hookSspi, 500);

// Timezone experiment: make GetLocalTime return UTC, matching the server clock.
let __timeCount = 0;
try {
  const __k32 = Process.getModuleByName("kernel32.dll");
  const __gst = __k32.getExportByName("GetSystemTime");
  const __gstFn = new NativeFunction(__gst, "void", ["pointer"]);
  const __glt = __k32.getExportByName("GetLocalTime");
  Interceptor.attach(__glt, {
    onEnter(args) { this.out = args[0]; },
    onLeave(ret) {
      __gstFn(this.out);
      if (__timeCount++ % 200 === 0) send({timeHook: "GetLocalTime->UTC", count: __timeCount});
    }
  });
  send({timeHook: "installed"});
} catch (e) {
  send({timeHookErr: String(e)});
}
