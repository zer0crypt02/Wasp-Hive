#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  OpenCode API Proxy — NİHAİ KURULUM (Termux/Android)
#
#  opencode-termux projesinden derlenmiş binary kullanır.
#  npm gerekmez, glibc gerekmez.
#
#  Bu dosyayı Termux'ta çalıştır:
#    bash /sdcard/opencode-proxy/final-setup.sh
# ═══════════════════════════════════════════════════════════════
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  OpenCode API Proxy — NİHAİ KURULUM              ║${NC}"
echo -e "${CYAN}║  opencode-termux binary + Node.js proxy          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── 1. Bağımlılıklar ──
echo -e "${YELLOW}[1/6] Bağımlılıklar kuruluyor...${NC}"
pkg update -y -o Dpkg::Options::="--force-confnew" 2>/dev/null || true
pkg install -y nodejs curl unzip 2>&1 | tail -3
echo -e "${GREEN}  ✓ Node: $(node --version 2>&1)${NC}"

# ── 2. ripgrep kur (OpenCode gerekli) ──
echo -e "${YELLOW}[2/6] ripgrep kuruluyor...${NC}"
pkg install -y ripgrep 2>&1 | tail -2
echo -e "${GREEN}  ✓ ripgrep hazır${NC}"

# ── 3. OpenCode Termux binary indir ──
echo -e "${YELLOW}[3/6] OpenCode Termux binary indiriliyor...${NC}"

OPENCODE_VERSION="1.17.9"
ZIP_URL="https://github.com/guysoft/opencode-termux/releases/download/v${OPENCODE_VERSION}/opencode-${OPENCODE_VERSION}-android-aarch64.zip"
TMP_DIR="${TMPDIR:-$HOME/tmp}/opencode-install"
mkdir -p "$TMP_DIR"

echo -e "  → URL: $ZIP_URL"
curl -fsSL -o "$TMP_DIR/opencode.zip" "$ZIP_URL" 2>&1 || {
    # Alternatif: en son release
    echo -e "${YELLOW}  → Version bulunamadı, en son release deneniyor...${NC}"
    ZIP_URL="https://github.com/guysoft/opencode-termux/releases/latest/download/opencode-android-aarch64.zip"
    curl -fsSL -o "$TMP_DIR/opencode.zip" "$ZIP_URL" 2>&1 || {
        echo -e "${YELLOW}  → v1.3.13 deneniyor...${NC}"
        ZIP_URL="https://github.com/guysoft/opencode-termux/releases/download/v1.3.13-tagfix29/opencode-1.3.13-android-aarch64.zip"
        curl -fsSL -o "$TMP_DIR/opencode.zip" "$ZIP_URL"
    }
}

echo -e "  → İndirilen boyut: $(ls -lh "$TMP_DIR/opencode.zip" | awk '{print $5}')"

# Zip'i aç
cd "$TMP_DIR"
unzip -o opencode.zip 2>&1 | head -10

# Binary'leri $PREFIX/bin/ kopyala
echo -e "  → Binary'ler kuruluyor..."
for f in opencode opencode.bin libtagfix.so libc++_shared.so libopentui.so librust_pty_arm64.so; do
    if [ -f "$f" ]; then
        cp "$f" "$PREFIX/bin/"
        chmod +x "$PREFIX/bin/$f" 2>/dev/null || true
        echo -e "    ✓ $f"
    fi
done

# Debug variant varsa
for f in opencode-debug opencode-debug.bin; do
    if [ -f "$f" ]; then
        cp "$f" "$PREFIX/bin/"
        chmod +x "$PREFIX/bin/$f" 2>/dev/null || true
    fi
done

rm -rf "$TMP_DIR"
echo -e "${GREEN}  ✓ OpenCode binary kuruldu${NC}"

# ── 4. OpenCode test ──
echo -e "${YELLOW}[4/6] OpenCode test ediliyor...${NC}"
if opencode --version 2>&1; then
    echo -e "${GREEN}  ✅ OpenCode çalışıyor!${NC}"
else
    echo -e "${YELLOW}  ⚠ opencode --version hata verdi, ama devam ediyoruz...${NC}"
fi

# ── 5. Config oluştur ──
echo -e "${YELLOW}[5/6] Config oluşturuluyor...${NC}"
CONFIG_DIR="$HOME/.config/opencode"
mkdir -p "$CONFIG_DIR"

cat > "$CONFIG_DIR/opencode.json" << 'CONF'
{
  "$schema": "https://opencode.ai/config.json",
  "model": "opencode/gpt-5-nano",
  "default_agent": "build",
  "autoCompact": true,
  "tui": {
    "theme": "opencode"
  }
}
CONF
echo -e "${GREEN}  ✓ Config: $CONFIG_DIR/opencode.json${NC}"

# ── 6. Proxy dosyalarını hazırla ──
echo -e "${YELLOW}[6/6] Proxy hazırlanıyor...${NC}"
PROXY_DIR="$HOME/opencode-proxy"
mkdir -p "$PROXY_DIR"

# server.js kopyala
if [ -f "/sdcard/opencode-proxy/server.js" ]; then
    cp /sdcard/opencode-proxy/server.js "$PROXY_DIR/server.js"
    echo -e "${GREEN}  ✓ server.js${NC}"
else
    echo -e "${RED}  ✗ server.js bulunamadı!${NC}"
    exit 1
fi

# OPENCODE_BIN yolunu ayarla
REAL_OPENCODE=$(command -v opencode 2>/dev/null || echo "/data/data/com.termux/files/usr/bin/opencode")

# start.sh oluştur
cat > "$PROXY_DIR/start.sh" << STARTEOF
#!/bin/bash
cd "$PROXY_DIR"
export OPENCODE_BIN="$REAL_OPENCODE"
export PORT=3001
export DEFAULT_MODEL="opencode/gpt-5-nano"
echo "🚀 OpenCode API Proxy başlatılıyor..."
MY_IP=\$(ip route get 1 2>/dev/null | awk '{print \$7; exit}')
echo "📱 Telefon IP: \$MY_IP"
echo "🌐 Port: \$PORT"
echo ""
echo "Bilgisayarından erişim:"
echo "  curl http://\$MY_IP:3001/health"
echo ""
node server.js
STARTEOF
chmod +x "$PROXY_DIR/start.sh"

# test.sh
cat > "$PROXY_DIR/test.sh" << 'TESTEOF'
#!/bin/bash
PORT=3001
echo "🧪 Testing OpenCode API Proxy..."
echo ""
echo "━━━ Health ━━━"
curl -s http://localhost:$PORT/health
echo ""
echo ""
echo "━━━ Chat ━━━"
curl -s -X POST http://localhost:$PORT/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"opencode/gpt-5-nano","messages":[{"role":"user","content":"Merhaba, tek kelime ile yanıt ver: selam"}]}'
echo ""
TESTEOF
chmod +x "$PROXY_DIR/test.sh"

# ── Bitiş ──
MY_IP=$(ip route get 1 2>/dev/null | awk '{print $7; exit}')

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        ✅ NİHAİ KURULUM TAMAM!                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}1️⃣  Proxy'yi başlat:${NC}"
echo -e "    ${GREEN}cd ~/opencode-proxy && bash start.sh${NC}"
echo ""
echo -e "${CYAN}2️⃣  Bilgisayarından eriş:${NC}"
echo -e "    ${GREEN}curl http://${MY_IP}:3001/health${NC}"
echo ""
echo -e "${CYAN}3️⃣  Test et:${NC}"
echo -e "    ${GREEN}bash ~/opencode-proxy/test.sh${NC}"
echo ""
