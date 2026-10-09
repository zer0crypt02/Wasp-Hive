#!/bin/bash
# ═══════════════════════════════════════════════════════
#  Node.js OpenSSL Hatası Düzeltme (Termux)
#
#  Hata: cannot locate symbol "OSSL_PROVIDER_add_conf_parameter"
#
#  Bu dosyayı Termux'ta çalıştır:
#    bash /sdcard/opencode-proxy/fix-node.sh
# ═══════════════════════════════════════════════════════
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}🔧 Node.js OpenSSL hatası düzeltiliyor...${NC}"
echo ""

# ── Adım 1: Tüm paketleri güncelle ──
echo -e "${YELLOW}[1/4] Tüm paketler güncelleniyor...${NC}"
pkg update -y -o Dpkg::Options::="--force-confnew" 2>&1 | tail -3
pkg upgrade -y -o Dpkg::Options::="--force-confnew" 2>&1 | tail -3
echo -e "${GREEN}  ✓ Paketler güncellendi${NC}"

# ── Adım 2: OpenSSL'i güncelle ──
echo -e "${YELLOW}[2/4] OpenSSL güncelleniyor...${NC}"
pkg install -y openssl 2>&1 | tail -3
echo -e "${GREEN}  ✓ OpenSSL güncellendi${NC}"

# ── Adım 3: Node.js'i yeniden kur ──
echo -e "${YELLOW}[3/4] Node.js yeniden kuruluyor...${NC}"
pkg install -y nodejs 2>&1 | tail -5
echo -e "${GREEN}  ✓ Node.js kuruldu${NC}"

# ── Adım 4: Test ──
echo -e "${YELLOW}[4/4] Test ediliyor...${NC}"
if node --version 2>&1; then
    echo -e "${GREEN}  ✅ Node.js çalışıyor!${NC}"
else
    echo -e "${RED}  ❌ Node.js hala hatalı. Alternatif deneniyor...${NC}"
    echo ""

    # Alternatif: nvm ile kur
    echo -e "${YELLOW}  nvm ile Node.js kuruluyor...${NC}"
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash 2>&1 | tail -3
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    nvm install 20 2>&1 | tail -5
    nvm use 20
    echo -e "${GREEN}  ✓ nvm ile Node.js kuruldu: $(node --version)${NC}"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ Düzeltme tamamlandı!             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Şimdi kuruluma devam et:${NC}"
echo -e "  ${GREEN}bash /sdcard/opencode-proxy/install.sh${NC}"
echo ""
