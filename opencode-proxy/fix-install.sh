#!/bin/bash
# ═══════════════════════════════════════════════════════
#  OpenCode API Proxy — Düzeltilmiş Kurulum (Termux/Android)
#
#  npm android OS tanımıyor → --force ile atlıyoruz
#
#  Bu dosyayı Termux'ta çalıştır:
#    bash /sdcard/opencode-proxy/fix-install.sh
# ═══════════════════════════════════════════════════════
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  OpenCode API Proxy — Android Düzeltme       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ── 1. Node.js kontrol ──
echo -e "${YELLOW}[1/5] Node.js kontrol ediliyor...${NC}"
if ! node --version 2>/dev/null; then
    echo -e "${RED}  ✗ Node.js çalışmıyor! Önce fix-node.sh çalıştır:${NC}"
    echo -e "    ${GREEN}bash /sdcard/opencode-proxy/fix-node.sh${NC}"
    exit 1
fi
echo -e "${GREEN}  ✓ Node: $(node --version)${NC}"
echo -e "${GREEN}  ✓ npm: $(npm --version)${NC}"

# ── 2. npm os kısıtlamasını bypass et ──
echo -e "${YELLOW}[2/5] OpenCode kuruluyor (--force ile Android bypass)...${NC}"

# Yöntem 1: npm --force
if npm install -g opencode-ai --force 2>&1 | tail -5; then
    if command -v opencode &>/dev/null; then
        echo -e "${GREEN}  ✓ opencode bulundu: $(which opencode)${NC}"
    fi
fi

# Yöntem 1 başarısızsa → Yöntem 2: Manuel binary indir
if ! command -v opencode &>/dev/null; then
    echo -e "${YELLOW}  npm başarısız, alternatif yöntem deneniyor...${NC}"
    echo -e "${YELLOW}[3/5] OpenCode binary indiriliyor...${NC}"

    # GitHub releases'tan linux-arm64 binary indir
    # opencode-ai/opencode (archived) veya anomalyco/opencode
    ARCH="arm64"
    URL="https://github.com/anomalyco/opencode/releases/latest/download/opencode-linux-${ARCH}"

    echo -e "  → İndiriliyor: $URL"
    curl -fsSL "$URL" -o /data/data/com.termux/files/usr/bin/opencode 2>&1 || {
        # Alternatif URL
        URL2="https://github.com/opencode-ai/opencode/releases/latest/download/opencode-linux-${ARCH}"
        echo -e "  → Alternatif URL deneniyor: $URL2"
        curl -fsSL "$URL2" -o /data/data/com.termux/files/usr/bin/opencode 2>&1
    }
    chmod +x /data/data/com.termux/files/usr/bin/opencode 2>/dev/null || true
fi

# Yöntem 2 de başarısızsa → Yöntem 3: /sdcard'daki binary'yi kullan
if ! command -v opencode &>/dev/null; then
    echo -e "${YELLOW}[3/5] /sdcard/opencode deneniyor...${NC}"
    if [ -f "/sdcard/opencode" ]; then
        cp /sdcard/opencode /data/data/com.termux/files/usr/bin/opencode
        chmod +x /data/data/com.termux/files/usr/bin/opencode
        echo -e "${GREEN}  ✓ /sdcard/opencode kopyalandı${NC}"
    else
        echo -e "${RED}  ✗ Hiçbir OpenCode kaynağı bulunamadı!${NC}"
        echo -e "${YELLOW}    Manuel olarak /sdcard/opencode konumuna koy.${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}  ✓ OpenCode: $(which opencode)${NC}"
echo -e "${GREEN}  ✓ Version: $(opencode --version 2>&1 || echo 'check manually')${NC}"

# ── 4. Config oluştur ──
echo -e "${YELLOW}[4/5] Config oluşturuluyor...${NC}"
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

# ── 5. Proxy dosyalarını hazırla ──
echo -e "${YELLOW}[5/5] Proxy hazırlanıyor...${NC}"
PROXY_DIR="$HOME/opencode-proxy"
mkdir -p "$PROXY_DIR"

if [ -f "/sdcard/opencode-proxy/server.js" ]; then
    cp /sdcard/opencode-proxy/server.js "$PROXY_DIR/server.js"
    echo -e "${GREEN}  ✓ server.js kopyalandı${NC}"
else
    echo -e "${RED}  ✗ server.js bulunamadı! /sdcard/opencode-proxy/ kontrol et.${NC}"
    exit 1
fi

# Start script
cat > "$PROXY_DIR/start.sh" << STARTEOF
#!/bin/bash
cd "$PROXY_DIR"
export OPENCODE_BIN="\$(command -v opencode)"
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

# Test script
cat > "$PROXY_DIR/test.sh" << 'TESTEOF'
#!/bin/bash
PORT=3001
echo "🧪 Testing OpenCode API Proxy..."
echo ""
echo "━━━ Health ━━━"
curl -s http://localhost:$PORT/health | python3 -m json.tool 2>/dev/null || curl -s http://localhost:$PORT/health
echo ""
echo ""
echo "━━━ Chat ━━━"
curl -s -X POST http://localhost:$PORT/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"opencode/gpt-5-nano","messages":[{"role":"user","content":"Merhaba, tek kelime ile yanıt ver: selam"}]}' \
  | python3 -m json.tool 2>/dev/null
TESTEOF
chmod +x "$PROXY_DIR/test.sh"

# ── Bitiş ──
MY_IP=$(ip route get 1 2>/dev/null | awk '{print $7; exit}')

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        ✅ KURULUM TAMAM!                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Proxy'yi başlat:${NC}"
echo -e "  ${GREEN}cd ~/opencode-proxy && bash start.sh${NC}"
echo ""
echo -e "${CYAN}Bilgisayarından eriş:${NC}"
echo -e "  ${GREEN}curl http://${MY_IP}:3001/health${NC}"
echo ""
