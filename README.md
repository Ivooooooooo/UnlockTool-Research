# UnlockTool 2026.11.05.0: security review

I spent a couple of days in November 2026 looking at UnlockTool 2026.11.05.0. What started as a
question about the login flow ended up being a review of how the client gates its main window, how
Themida/WinLicense reacts when that gate is bypassed, and what the app actually asks the backend for.
This repository is the handover: the findings, the runtime proof of concept, the scripts I used, and
the one screenshot that matters.

**No binaries are included.** They are large. The installer I worked from is `UnlockTool-2026-11-05-0.exe`, SHA-256:
```
F2E2BA536003CFEEF0E3D4342CF082E83E2309C33E5A55B13FEA9D967F93ACD7
```

That hash is the original file. Nothing on disk was patched; every change described here happens in
memory after the process starts.

## The build

| | |
|---|---|
| Version | `2026.11.05.0` |
| Format | PE32 (x86), Delphi/VCL with DevExpress (cx) controls |
| Protector | Themida / WinLicense (Oreans) |
| Installer | 225,155,824 bytes, SHA-256 above |
| Unpacked module I worked from | 491,245,568 bytes, SHA-256 `EB2681FBC7A80A3D278504BF2D1915DFF9AD8B03DAA59727C64B8781BDBAA541` |
| Image base | `0x400000` |
| Manifest | `requestedExecutionLevel level="requireAdministrator"` |
| Backend | https://vntool.vn/apiv4r21/ |
| Data host | https://mtk.unlocktool.net/ (same address as `bypass.vntools.net`) |
| Telegram | https://t.me/pelixx7 |

The app extracts itself to `C:\UnlockTool` on first run. It is 32-bit, so it runs under WOW64 on a
normal x64 machine. The manifest asks for administrator; for the UI tests I ran it with
`__COMPAT_LAYER=RunAsInvoker` when elevation was not the variable under test.

## What I found

Four things, ordered by how much they matter.

1. **The local UI gate can be skipped.** The login form is an ordinary VCL form, and the app decides
   whether it was dismissed successfully from the form's own `ModalResult`. Writing `mrOk` into that
   field makes the app proceed to its main window without a server session. The window that opens is
   the real one, not a stub: every vendor button, the ADB/FASTBOOT/T.POINT tools, the USB/COM
   selectors, the progress bars, and all the chipset tabs are there.

2. **Themida/WinLicense notices and tries to kill the process.** Once the login is faked, the
   protector calls `TerminateProcess(0xFFFFFFFF, 0xDEADC0DE)` and raises an access-violation message
   box. That is a local check, not a server response. The exit code is the giveaway; `0xDEADC0DE` is
   the protector's own poison value. The check lives in the packed section, not in the Delphi code.

3. **The message boxes can be suppressed at runtime.** The straightforward ones go through
   `MessageBoxW/A`, `MessageBoxEx*`, `MessageBoxIndirect*`, `MessageBoxTimeout*`,
   `SHMessageBoxCheck*`, and `DialogBoxParam*`. The serial dialog is different: it is created and
   pumped by the protector itself, so the `user32` hooks never see it. What works there is an
   external watcher that polls for a `#32770` window belonging to the process and posts `IDOK` /
   `WM_CLOSE` to it.

4. **The HTTPS relay is a red herring for this gate.** I built a local CA, added hosts entries, and
   proxied `vntool.vn`, `mtk.unlocktool.net`, and `bypass.vntools.net` through a small TLS server.
   It works; Schannel/Indy talk to it happily, and I could watch the media downloads. But the serial
   check that blocks the UI is local. A relay that "accepts the key" does not change it.

If you only fix one thing, make the client stop trusting its own `ModalResult` for authentication
state. The rest make the product easier to copy or misuse; the first one removes the local gate
entirely.

## Login flow notes

The login form is a Delphi VCL form, class `TFormLogin`, title `UNLOCKTOOL 2026.11.05.0 -
https://unlocktool.net`. The controls I could see:

- `edtUsername` (`TcxButtonEdit` with an inner `TcxCustomInnerTextEdit`)
- `edtPassword` (same pattern)
- `btnSignIn` (`TcxButton`, caption `Login`)
- `checkRemember`, `cbLanguages`, `cbTheme`
- links `Register`, `Reset Password`, `VPN`, `Forum`

The controller class is `TLoginController`, with fields `FTimeKey`, `FTimeKey2`, `FEKey` and methods
`SignIn` and `CheckUpdate`. The button handler, `btnSignInClick` at RVA `0x146CB68`, is virtualized:
the prologue is normal, then it calls `0x554DF9F` and disappears into Themida bytecode. RetDec output
for that function is not usable.

The API base is `https://vntool.vn/apiv4r21/`. Two GETs fire when the button is pressed:

```http
GET /apiv4r21/update/?format=json&tool_name__name__iexact=UnlockTool HTTP/1.1
Host: vntool.vn
User-Agent: UnlockTool
```

The response is a JSON array of about 60 tool entries (`id`, `tool_name`, `version`, `changelog`,
`download_link`, `create_date`, `filename`, `md5_hash`). The version returned is `2026.11.05.0`, the
same as the binary. There is no licence field and no auth key in it.

```http
GET /apiv4r21/current_time HTTP/1.1
Host: vntool.vn
User-Agent: UnlockTool
```

That one redirects 301 to `/apiv4r21/current_time/` and returns:

```json
{"data": "2026-11-06 19:14:13.487752"}
```

The network stack is Schannel/SSPI (`sspicli.dll`, `secur32.dll`, `ncryptsslp.dll`). It is not
WinHTTP; the `WinHttp*` exports never fire. It is not Chilkat either, at least not for the login:
`unlocktool2.dll` is a renamed Chilkat (887 `Ck*` exports loaded from memory), but none of its
`CkHttp_*` or `CkSocket_*` functions are called during login.

Hooking `sspicli!EncryptMessage` / `DecryptMessage` shows the two GETs above. **No login POST ever
appears**, with or without Frida, on a normal desktop or a hidden one, elevated or not. Pressing
Login non-elevated produces a `#32770` titled `Unlocktool-2026-11-05-0` with an `Aceptar` button and
the text `Acceso denegado.` — that is Windows `ERROR_ACCESS_DENIED` (5), not a server answer.
Elevated, the dialog goes away, a new TLS connection opens, and still no POST is sent.

My working hypotheses, for whoever picks this up:

1. The VM handler checks something locally before sending anything, and the `Acceso denegado` path is
   that check failing.
2. The handler may expect elevation, a prior registration, or a local licence/session
   (`TAppConfig` exposes `IsLoginCheck`, `LoginUsername`, `AuthKey`, `CERT_CHECK`, `CERT_PORT`).
3. There may be a separate login endpoint (or a different TLS stack) I never reached because the
   handler bails out first.

A valid test account from the vendor would settle most of this in ten minutes.

## Local UI bypass

This is the part that works today. It is runtime only; the EXE on disk is untouched.

The key field is `TCustomForm.ModalResult` at `Self + 0x2FC`. The modal loop in `ShowModal` reads it
on every iteration and closes the form with `mrOk` when it is non-zero. The `TFormLogin` class
reference is `0x0186B1F0`. To find the live instance I scan writable memory for that value, check the
class name at `vmt - 56`, and require `+0x69 (Visible) == 1` and `+0x2FC == 0`. Then I write `1`.

With the login out of the way the app creates `TUnlockTool` itself, with the correct title, behind a
`TFormProcessing` window that says `Processing...`. Two details matter:

- **Do not hide `TFormProcessing` with `SW_HIDE`.** That trips a `DEADC0DE` crash path. Move it
  off-screen with `SetWindowPos(-32000, -32000, ...)` instead.
- Show `TUnlockTool` with `SW_SHOW` and bring it to the foreground.

The protector still fires its anti-tamper checks while the window is up. The guard catches them: the
message box never reaches the screen and `TerminateProcess` never gets to run.

Evidence: `PoC/evidence/bypass-final.png`. The window is 1453x915 and shows the full interface.

## Message boxes and the serial dialog

The first version only suppressed the serial text. That was not enough: the protector also shows
`Access violation at address ... Read of address DEADC0DE.` and, later, an execution error at
`0x593`. The current guard returns `IDOK` for every message box, so none of them appear.

The list of replaced exports is in `PoC/hook_guard.js`:

- `MessageBoxW/A`, `MessageBoxExW/ExA`
- `MessageBoxIndirectW/A`, `MessageBoxTimeoutW/A`
- `SHMessageBoxCheckW/A`
- `DialogBoxParamW/A`, `DialogBoxIndirectParamW/A`
- `ExitProcess`, `RtlExitUserProcess`, `NtTerminateProcess`, `TerminateProcess`

There is also a `WinEvent` hook for `EVENT_OBJECT_CREATE` through `EVENT_OBJECT_SHOW`. It helps, but
it is not sufficient on its own: the serial dialog is created and pumped by the protector, so the
event may sit in a queue that the protector's own loop never dispatches. That is why
`run_bypass.py` starts a small watcher thread. Every 200 ms it enumerates top-level windows, and if
it sees a `#32770` owned by the app it hides it and posts `WM_COMMAND` with `IDOK` followed by
`WM_CLOSE`. This is the piece that finally keeps the serial box off the screen.

One caveat: because every message box is suppressed, legitimate confirmations the app might want to
show are suppressed too. That is what was asked for, but it is worth knowing if a feature appears to
do nothing.

## The relay experiment

I built this before I understood that the serial check is local, and I am leaving it here because it
is useful for watching traffic.

`PoC/certs/mkcerts.py` creates a small CA and a server certificate with SANs for `vntool.vn`,
`bypass.vntools.net`, `mtk.unlocktool.net`, and `ut-data.vntool.net`. `setup_relay.ps1` installs the
CA into `LocalMachine\Root` and adds hosts entries. `relay_server.py` listens on 443 and proxies to
the real hosts, logging requests and responses. `cleanup_relay.ps1` removes the CA and restores the
hosts file.

It works. `GET /media/mtk_emi.txt` and `GET /media/exy_set.txt` return URLs pointing at
`mtk.unlocktool.net/uploads/...`, and the app then downloads the real files through the relay. But
nothing in that path decides whether the UI opens. The gate is WinLicense, locally.

## Secrets
**Test credentials used for the form.** I did not have a valid account, so I used throwaway values:

| Field | Value |
|---|---|
| Username | `test@example.com` |
| Password | `Test12345!` |

The server answered `Invalid USERNAME/PASSWORD or Server timeout! Error code: 400 - State: Query
Access`. As noted above, the real login request never left the client in the flow I could observe.

**Relay CA and keys.** The private material lives in `PoC/certs/`:

| File | What it is |
|---|---|
| `ca_key.pem` | CA private key (RSA 2048) |
| `ca_cert.pem` / `ca_cert.der` | CA certificate (`UnlockTool Security Lab CA`) |
| `server_key.pem` | Server private key (RSA 2048) |
| `server_chain.pem` | Server certificate plus CA, SANs listed above |

The CA thumbprint I installed was `B26F3C018B665F89508327DDDCE04E0FF07AD592`. It was removed again
with `cleanup_relay.ps1`.

**Hashes.**

| Artefact | SHA-256 |
|---|---|
| Original ZIP | `e97657d7e56923968be8bf4c2595c7c085b992e7fa925ebe4dba147db0de36e5` |
| Installer (`UnlockTool-2026-11-05-0.exe`) | `F2E2BA536003CFEEF0E3D4342CF082E83E2309C33E5A55B13FEA9D967F93ACD7` |
| Unpacked module | `EB2681FBC7A80A3D278504BF2D1915DFF9AD8B03DAA59727C64B8781BDBAA541` |

If this repository ever stops being private, rotate the webhook and treat the CA keys as burned.

## Reproduction

You need Windows x64, Python 3.11 or newer, and an elevated console (the app's manifest requires
administrator).

```powershell
cd PoC
pip install -r requirements.txt
python run_bypass.py
```

`run_bypass.py` launches the installer, attaches Frida, installs the guard, waits for `TFormLogin`,
writes `mrOk`, waits for `TFormProcessing` and `TUnlockTool`, moves the processing window off-screen,
shows the main window, and keeps the guard alive until you close the console. Close the console and
the protector gets its way again.

The other scripts are supporting material: `frida_http.py` has the desktop and window helpers,
`login_normal.py` fills and clicks the form, `check_windows.py` lists what the process owns,
`delphi_vmt.py` parses Delphi VMTs and method tables, `hook_schannel.js` and `hook_login_all.js`
capture the TLS plaintext, and the `decompiled/` folder has the RetDec output for the login and auth
ranges.

## Files

```
README.md
PoC/
  run_bypass.py            main PoC
  hook_guard.js            message boxes, exits, WinEvent hook
  hook_modal.js            ModalResult write + WinEvent hook
  frida_http.py            Frida/desktop helpers
  login_normal.py          form fill/click helpers
  check_windows.py         window enumeration
  delphi_vmt.py            VMT/method table parser
  send_webhook.py          webhook notifier
  kill_all.ps1             stop leftover processes (admin)
  hook_schannel.js         TLS plaintext capture
  hook_login_all.js        network/file/registry hooks
  certs/                   CA, server cert, keys, relay server, setup/cleanup
  decompiled/              RetDec: login-low, login, auth, c7
  evidence/bypass-final.png
  requirements.txt
```

## Limitations

The bypass is runtime only. It depends on the Frida session staying attached, and the protector will
keep raising anti-tamper checks in the background. The UI opens, but anything that needs a real
account or a server session still needs one. And the login POST itself is still an open question:
the handler is virtualized and I could not get it to send anything without a valid account.

If someone has a vendor test account, the next step is easy: capture the request and response from a
successful login, and compare it with the local checks in `TLoginController`. That would tell us
whether the `Acceso denegado` path is a client-side precondition or the tail end of a request that
uses a stack I did not hook.
