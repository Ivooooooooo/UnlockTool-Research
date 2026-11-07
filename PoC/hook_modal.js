const main = Process.getModuleByName("UnlockTool-2026-11-05-0.exe");
const BASE = main.base;

function shortStr(p) {
  try { const n = p.readU8(); if (n === 0 || n > 200) return null; return p.add(1).readUtf8String(n); }
  catch (e) { return null; }
}
function className(obj) {
  try { return shortStr(obj.readPointer().sub(56).readPointer()); } catch (e) { return null; }
}

const LOGIN_CLASSREF = 0x186B1F0;
const MODAL_RESULT_OFF = 0x2FC;
const VISIBLE_OFF = 0x69;

let winEventCb = null;
let winEventInstalled = false;
let dialogCount = 0;

function installWinEvent() {
  if (winEventInstalled) return;
  winEventInstalled = true;
  try {
    const u32 = Process.getModuleByName("user32.dll");
    const GetClassNameW = new NativeFunction(u32.getExportByName("GetClassNameW"), "int", ["pointer", "pointer", "int"], "stdcall");
    const ShowWindowF = new NativeFunction(u32.getExportByName("ShowWindow"), "int", ["pointer", "int"], "stdcall");
    const PostMessageW = new NativeFunction(u32.getExportByName("PostMessageW"), "int", ["pointer", "uint", "pointer", "pointer"], "stdcall");

    winEventCb = new NativeCallback(function (hook, event, hwnd, idObject, idChild, tid, time) {
      try {
        if (idObject !== 0 || idChild !== 0) return;
        const buf = Memory.alloc(128);
        GetClassNameW(hwnd, buf, 64);
        const cls = buf.readUtf16String();
        if (cls === "#32770") {
          if (dialogCount < 40) { dialogCount++; send({ winEventDialog: cls, event: event }); }
          ShowWindowF(hwnd, 0);                          // SW_HIDE
          PostMessageW(hwnd, 0x0111, ptr(1), ptr(0));    // WM_COMMAND IDOK
          PostMessageW(hwnd, 0x0010, ptr(0), ptr(0));    // WM_CLOSE
        }
      } catch (e) {}
    }, "void", ["pointer", "uint", "pointer", "int", "int", "uint", "uint"]);

    const SetWinEventHook = new NativeFunction(
      u32.getExportByName("SetWinEventHook"), "pointer",
      ["uint", "uint", "pointer", "pointer", "uint", "uint", "uint"], "stdcall");
    // EVENT_OBJECT_CREATE(0x8000) .. EVENT_OBJECT_SHOW(0x8002), WINEVENT_OUTOFCONTEXT(0)
    const h = SetWinEventHook(0x8000, 0x8002, ptr(0), winEventCb, 0, 0, 0);
    send({ winEventHook: h.toString() });
  } catch (e) { send({ winEventErr: String(e) }); }
}

function findLoginForms() {
  const out = [];
  let ranges = [];
  try { ranges = Process.enumerateRanges("rw-"); } catch (e) { return out; }
  const pat = "f0 b1 86 01"; // 0x0186B1F0
  for (const r of ranges) {
    if (r.base.compare(BASE) >= 0 && r.base.compare(BASE.add(main.size)) < 0) continue;
    let found = [];
    try { found = Memory.scanSync(r.base, r.size, pat); } catch (e) { continue; }
    for (const f of found) {
      const obj = f.address;
      if (className(obj) !== "TFormLogin") continue;
      let vis = null, modal = null, hwnd = null;
      try { vis = obj.add(VISIBLE_OFF).readU8(); } catch (e) {}
      try { modal = obj.add(MODAL_RESULT_OFF).readU32(); } catch (e) {}
      out.push({ addr: obj.toString(), vis: vis, modal: modal });
    }
    if (out.length > 8) break;
  }
  return out;
}

let done = false;
function probe() {
  const forms = findLoginForms();
  send({ stage: "scan", forms: forms });

  let n = 0;
  for (const f of forms) {
    // only the live, visible login form with a clean modal result
    if (f.vis !== 1 || f.modal !== 0) continue;
    const o = ptr(f.addr);
    try {
      const before = o.add(MODAL_RESULT_OFF).readU32();
      o.add(MODAL_RESULT_OFF).writeU32(1);
      const after = o.add(MODAL_RESULT_OFF).readU32();
      n++;
      send({ stage: "set-modal", addr: f.addr, before: before, after: after });
    } catch (e) { send({ stage: "set-modal-error", addr: f.addr, e: String(e) }); }
  }
  send({ stage: "done", written: n });
}

try {
  const addr = Process.getModuleByName("user32.dll").getExportByName("PeekMessageW");
  Interceptor.attach(addr, {
    onEnter() {
      if (done) return;
      done = true;
      send({ stage: "hook-hit", thread: Process.getCurrentThreadId() });
      try { installWinEvent(); } catch (e) { send({ stage: "winevent-error", e: String(e) }); }
      try { probe(); } catch (e) { send({ stage: "probe-error", e: String(e) }); }
    }
  });
  send({ hooked: "PeekMessageW" });
} catch (e) { send({ hookErr: String(e) }); }
