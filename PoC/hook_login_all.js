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
    send({label: label, len: len, text: txt.slice(0, 3000)}, bytes);
  } catch (e) {}
}

function tryStr(p) {
  try { if (p.isNull()) return null; return p.readUtf8String(512); } catch (e) { return null; }
}
function tryW(p) {
  try { if (p.isNull()) return null; return p.readUtf16String(512); } catch (e) { return null; }
}

// ---------------- Schannel / SSPI ----------------
let sspiHooked = false;
function hookSspi() {
  if (sspiHooked) return;
  const m = Process.findModuleByName("sspicli.dll");
  if (!m) return;
  for (const fn of ["EncryptMessage", "DecryptMessage"]) {
    let p = null;
    try { p = m.getExportByName(fn); } catch (e) { p = m.findExportByName(fn); }
    if (!p) continue;
    try {
      Interceptor.attach(p, {
        onEnter(args) {
          try {
            const desc = (fn === "EncryptMessage") ? args[2] : args[1];
            const cBuffers = desc.add(4).readU32();
            const pBuffers = desc.add(8).readPointer();
            for (let i = 0; i < cBuffers; i++) {
              const b = pBuffers.add(i * 12);
              const cb = b.readU32();
              const type = b.add(4).readU32();
              const pv = b.add(8).readPointer();
              if (type === 1 && cb > 0) {
                if (fn === "EncryptMessage") emit("ENC", pv, cb);
                else { this.bufs = this.bufs || []; this.bufs.push({b: b}); }
              }
            }
          } catch (e) {}
        },
        onLeave(ret) {
          if (fn === "DecryptMessage" && this.bufs) {
            for (const x of this.bufs) {
              try {
                const cb = x.b.readU32();
                const pv = x.b.add(8).readPointer();
                if (cb > 0) emit("DEC", pv, cb);
              } catch (e) {}
            }
          }
        }
      });
      send({hookedSspi: fn});
    } catch (e) {}
  }
  sspiHooked = true;
}

// ---------------- OpenSSL ----------------
const sslHooked = {};
function hookSsl(name) {
  const m = Process.findModuleByName(name);
  if (!m) return;
  for (const fn of ["SSL_write", "SSL_read", "SSL_write_ex", "SSL_read_ex", "BIO_write", "BIO_read"]) {
    let p = null;
    try { p = m.getExportByName(fn); } catch (e) { p = m.findExportByName(fn); }
    if (!p || sslHooked[name + "!" + fn]) continue;
    try {
      Interceptor.attach(p, {
        onEnter(args) {
          if (fn === "SSL_write" || fn === "SSL_write_ex" || fn === "BIO_write") {
            const len = args[2].toInt32();
            if (len > 0 && len < 65536) emit(fn, args[1], len);
          } else {
            this.buf = args[1];
            this.outlen = (fn === "SSL_read_ex" || fn === "BIO_read") ? args[3] : null;
          }
        },
        onLeave(ret) {
          if (fn === "SSL_read" && ret.toInt32() > 0) emit("SSL_read", this.buf, ret.toInt32());
          if (fn === "SSL_read_ex" && ret.toInt32() === 1 && this.outlen) {
            try { const n = this.outlen.readU32(); if (n > 0) emit("SSL_read_ex", this.buf, n); } catch (e) {}
          }
          if (fn === "BIO_read" && ret.toInt32() > 0) emit("BIO_read", this.buf, ret.toInt32());
        }
      });
      sslHooked[name + "!" + fn] = true;
      send({hookedSsl: name + "!" + fn});
    } catch (e) {}
  }
}

function pollMods() {
  let mods = [];
  try { mods = Process.enumerateModules(); } catch (e) { return; }
  for (const m of mods) {
    if (/ssl|crypto|eay|gnutls|mbedtls/i.test(m.name)) {
      hookSsl(m.name);
    }
  }
}

// ---------------- Winsock ----------------
function hookWs() {
  const m = Process.findModuleByName("ws2_32.dll");
  if (!m) return;
  const defs = {
    "send": { onEnter(a) { const n = a[2].toInt32(); if (n > 0 && n < 8192) emit("ws2_send", a[1], n); } },
    "WSASend": { onEnter(a) {
      try {
        const n = a[1].readU32();
        const buf = a[1].add(4).readPointer();
        if (n > 0 && n < 8192) emit("WSASend", buf, n);
      } catch (e) {}
    }},
    "connect": { onEnter(a) {
      try {
        const sa = a[1];
        const family = sa.readU16();
        const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
        let ip = "";
        if (family === 2) {
          const b = new Uint8Array(sa.add(4).readByteArray(4));
          ip = b[0] + "." + b[1] + "." + b[2] + "." + b[3];
        }
        send({connect: ip, port: port});
      } catch (e) {}
    }}
  };
  for (const fn in defs) {
    let p = null;
    try { p = m.getExportByName(fn); } catch (e) { p = m.findExportByName(fn); }
    if (!p) continue;
    try { Interceptor.attach(p, defs[fn]); send({hookedWs: fn}); } catch (e) {}
  }
}

// ---------------- File / registry failures ----------------
function hookFileApi() {
  const k32 = Process.getModuleByName("kernel32.dll");
  let p = null;
  try { p = k32.getExportByName("CreateFileW"); } catch (e) { p = k32.findExportByName("CreateFileW"); }
  if (p) {
    Interceptor.attach(p, {
      onEnter(args) { this.name = tryW(args[0]); },
      onLeave(ret) {
        if (ret.toInt32() === -1) {
          send({fileFail: this.name, err: this.lastError ? this.lastError.toInt32() : null});
        }
      }
    });
    send({hookedFile: "CreateFileW"});
  }
  const adv = Process.findModuleByName("advapi32.dll");
  if (adv) {
    let q = null;
    try { q = adv.getExportByName("RegOpenKeyExW"); } catch (e) { q = adv.findExportByName("RegOpenKeyExW"); }
    if (q) {
      Interceptor.attach(q, {
        onEnter(args) { this.name = tryW(args[1]); },
        onLeave(ret) { if (ret.toInt32() !== 0) send({regFail: this.name, err: ret.toInt32()}); }
      });
      send({hookedFile: "RegOpenKeyExW"});
    }
  }
}

hookSspi();
setInterval(hookSspi, 500);
pollMods();
setInterval(pollMods, 500);
hookWs();
hookFileApi();
