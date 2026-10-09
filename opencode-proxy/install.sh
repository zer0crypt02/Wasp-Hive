#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  OpenCode API Proxy — Tek Komut Kurulum (Termux)
#  Bu dosyayı Termux'ta çalıştır:
#    bash /sdcard/opencode-proxy/install.sh
# ═══════════════════════════════════════════════════════════════
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  OpenCode API Proxy — Hızlı Kurulum          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ── 1. Paketleri güncelle ve Node.js kur ──
echo -e "${YELLOW}[1/4] Paketler güncelleniyor...${NC}"
pkg update -y -o Dpkg::Options::="--force-confnew" 2>/dev/null || true
pkg install -y nodejs 2>/dev/null || {
    echo -e "${YELLOW}  npm ile deneniyor...${NC}"
    apt update && apt install -y nodejs
}
echo -e "${GREEN}  ✓ Node.js: $(node --version)${NC}"
echo -e "${GREEN}  ✓ npm: $(npm --version)${NC}"

# ── 2. OpenCode'yu npm ile kur ──
echo -e "${YELLOW}[2/4] OpenCode kuruluyor (npm)...${NC}"
npm install -g opencode-ai 2>&1 | tail -5
OPENCODE_BIN="$(which opencode)"
echo -e "${GREEN}  ✓ OpenCode kuruldu: $OPENCODE_BIN${NC}"
echo -e "${GREEN}  ✓ Version: $($OPENCODE_BIN --version 2>&1 || echo 'check failed')${NC}"

# ── 3. Config oluştur ──
echo -e "${YELLOW}[3/4] Config dosyası oluşturuluyor...${NC}"
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

# ── 4. Proxy dosyalarını hazırla ──
echo -e "${YELLOW}[4/4] Proxy dosyaları hazırlanıyor...${NC}"
PROXY_DIR="$HOME/opencode-proxy"
mkdir -p "$PROXY_DIR"

# /sdcard'dan kopyala (eğer varsa)
if [ -f "/sdcard/opencode-proxy/server.js" ]; then
    cp /sdcard/opencode-proxy/server.js "$PROXY_DIR/server.js"
    echo -e "${GREEN}  ✓ server.js kopyalandı${NC}"
else
    echo -e "${RED}  ✗ server.js /sdcard'da bulunamadı!${NC}"
    echo -e "${YELLOW}    Manuel olarak kopyalayın veya README'deki kodu yapıştırın.${NC}"
fi

# Start script
cat > "$PROXY_DIR/start.sh" << STARTEOF
#!/bin/bash
cd "$PROXY_DIR"
export OPENCODE_BIN="$OPENCODE_BIN"
export PORT=3001
export DEFAULT_MODEL="opencode/gpt-5-nano"
echo "🚀 OpenCode API Proxy başlatılıyor..."
echo "📱 Telefon IP: \$(ip route get 1 2>/dev/null | awk '{print \$7; exit}' || hostname -I | awk '{print \$1}')"
echo "🌐 Port: \$PORT"
echo ""
echo "Bilgisayarından erişim:"
echo "  curl http://<TELEFON_IP>:3001/health"
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

echo -e "${GREEN}  ✓ Proxy dosyaları hazır: $PROXY_DIR/${NC}"

# ── IP adresi ──
MY_IP=$(ip route get 1 2>/dev/null | awk '{print $7; exit}' || hostname -I | awk '{print $1}')

# ── Bitiş ──
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
echo -e "${CYAN}Test et:${NC}"
echo -e "  ${GREEN}bash ~/opencode-proxy/test.sh${NC}"
echo ""
echo -e "${CYAN}Python/OpenAI client ile kullan:${NC}"
echo -e "  ${GREEN}export OPENAI_BASE_URL=http://${MY_IP}:3001/v1${NC}"
echo -e "  ${GREEN}export OPENAI_API_KEY=dummy${NC}"
echo ""
