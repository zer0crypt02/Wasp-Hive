#!/bin/bash
# ═══════════════════════════════════════════════════════
# OpenCode API Proxy - Termux Setup Script
# ═══════════════════════════════════════════════════════
#
# Bu script Termux'ta OpenCode proxy server'ı kurar.
# Çalıştır: bash setup.sh
#
set -e

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   OpenCode API Proxy - Termux Kurulum    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── 1. Bağımlılıkları kontrol et ──
echo -e "${YELLOW}[1/5] Bağımlılıklar kontrol ediliyor...${NC}"

# Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}  ✗ Node.js bulunamadı. Yükleniyor...${NC}"
    pkg update -y
    pkg install -y nodejs
    echo -e "${GREEN}  ✓ Node.js yüklendi: $(node --version)${NC}"
else
    echo -e "${GREEN}  ✓ Node.js: $(node --version)${NC}"
fi

# OpenCode binary kontrolü
OPENCODE_BIN="/sdcard/opencode"
if [ ! -f "$OPENCODE_BIN" ]; then
    echo -e "${RED}  ✗ OpenCode binary bulunamadı: $OPENCODE_BIN${NC}"
    echo -e "${YELLOW}  → OpenCode'u /sdcard/opencode konumuna kopyalayın${NC}"
    echo -e "${YELLOW}  → Veya npm ile kurun: npm install -g opencode-ai${NC}"
    echo ""
    read -p "npm ile kurulsun mu? (y/n): " INSTALL_NPM
    if [ "$INSTALL_NPM" = "y" ]; then
        echo -e "${YELLOW}  npm ile OpenCode kuruluyor...${NC}"
        npm install -g opencode-ai
        OPENCODE_BIN="$(which opencode)"
        echo -e "${GREEN}  ✓ OpenCode kuruldu: $OPENCODE_BIN${NC}"
    else
        echo -e "${RED}  OpenCode gerekli! Kurulum durdu.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}  ✓ OpenCode binary: $OPENCODE_BIN${NC}"
    # Çalıştırma izni ver
    chmod +x "$OPENCODE_BIN" 2>/dev/null || true
fi

# ── 2. Config dosyasını kur ──
echo -e "${YELLOW}[2/5] Config dosyası kuruluyor...${NC}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# opencode config dizini
CONFIG_DIR="$HOME/.config/opencode"
mkdir -p "$CONFIG_DIR"

# Config dosyasını kopyala
if [ -f "$SCRIPT_DIR/opencode.json" ]; then
    cp "$SCRIPT_DIR/opencode.json" "$CONFIG_DIR/opencode.json"
    echo -e "${GREEN}  ✓ Config kopyalandı: $CONFIG_DIR/opencode.json${NC}"
else
    echo -e "${YELLOW}  ! opencode.json bulunamadı, elle oluşturuluyor...${NC}"
    cat > "$CONFIG_DIR/opencode.json" << 'CONF'
{
  "$schema": "https://opencode.ai/config.json",
  "agents": {
    "coder": {
      "model": "copilot.gpt-4o",
      "maxTokens": 16384
    },
    "summarizer": {
      "model": "copilot.gpt-4o-mini",
      "maxTokens": 4096
    }
  },
  "debug": false,
  "autoCompact": true,
  "tui": {
    "theme": "opencode"
  }
}
CONF
    echo -e "${GREEN}  ✓ Config oluşturuldu: $CONFIG_DIR/opencode.json${NC}"
fi

# ── 3. OpenCode test et ──
echo -e "${YELLOW}[3/5] OpenCode test ediliyor...${NC}"

if [ -f "$OPENCODE_BIN" ]; then
    # Version kontrolü
    VERSION=$("$OPENCODE_BIN" --version 2>&1 || echo "unknown")
    echo -e "${GREEN}  ✓ OpenCode version: $VERSION${NC}"

    # Basit test (hata verirse bile devam et)
    echo -e "${CYAN}  → Test: opencode run --format json 'test'...${NC}"
    TEST_OUTPUT=$("$OPENCODE_BIN" run --format json "say hello" 2>&1 || true)
    if echo "$TEST_OUTPUT" | grep -q '"type"'; then
        echo -e "${GREEN}  ✓ OpenCode JSON output çalışıyor!${NC}"
    else
        echo -e "${YELLOW}  ⚠ JSON output test başarısız (agent hatası olabilir)${NC}"
        echo -e "${YELLOW}    Ama proxy yine de çalışacaktır, devam edin.${NC}"
    fi
fi

# ── 4. Proxy server dosyalarını hazırla ──
echo -e "${YELLOW}[4/5] Proxy server dosyaları hazırlanıyor...${NC}"

# OpenCode binary yolunu server.js'e yaz
if [ -f "$SCRIPT_DIR/server.js" ]; then
    echo -e "${GREEN}  ✓ server.js bulundu${NC}"
else
    echo -e "${RED}  ✗ server.js bulunamadı!$NC"
    exit 1
fi

# ── 5. Otomatik başlatma ──
echo -e "${YELLOW}[5/5] Başlatma scripti oluşturuluyor...${NC}"

cat > "$SCRIPT_DIR/start.sh" << STARTEOF
#!/bin/bash
# OpenCode API Proxy - Başlatma scripti
# Kullanım: bash start.sh

cd "$SCRIPT_DIR"

export OPENCODE_BIN="$OPENCODE_BIN"
export PORT=3001
export DEFAULT_MODEL="opencode/gpt-5-nano"

echo "🚀 OpenCode API Proxy başlatılıyor..."
echo "📱 Phone IP: \$(hostname -I 2>/dev/null | awk '{print \$1}' || echo 'bilinmiyor')"
echo "🌐 Port: \$PORT"
echo ""

node server.js
STARTEOF
chmod +x "$SCRIPT_DIR/start.sh"
echo -e "${GREEN}  ✓ start.sh oluşturuldu${NC}"

# ── Bitiş ──
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        ✅ Kurulum Tamamlandı!            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Başlatmak için:${NC}"
echo -e "  cd $SCRIPT_DIR"
echo -e "  bash start.sh"
echo ""
echo -e "${CYAN}Bilgisayarından erişmek için:${NC}"
echo -e "  curl http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'PHONE_IP'):3001/health"
echo ""
echo -e "${CYAN}Test komutu:${NC}"
echo -e '  curl -X POST http://localhost:3001/v1/chat/completions \'
echo -e '    -H "Content-Type: application/json" \'
echo -e '    -d '\''{"messages":[{"role":"user","content":"Merhaba, nasılsın?"}],"model":"opencode/gpt-5-nano"}'\'''
echo ""
