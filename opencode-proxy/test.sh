#!/bin/bash
# ═══════════════════════════════════════════════════════
# OpenCode API Proxy - Test Script
# ═══════════════════════════════════════════════════════
set -e

BASE_URL="${1:-http://localhost:3001}"

echo "🧪 Testing OpenCode API Proxy at $BASE_URL"
echo ""

# 1. Health check
echo "━━━ [1/3] Health Check ━━━"
curl -s "$BASE_URL/health" | python3 -m json.tool 2>/dev/null || curl -s "$BASE_URL/health"
echo ""
echo ""

# 2. Models
echo "━━━ [2/3] Models ━━━"
curl -s "$BASE_URL/v1/models" | python3 -m json.tool 2>/dev/null || curl -s "$BASE_URL/v1/models"
echo ""
echo ""

# 3. Chat completion
echo "━━━ [3/3] Chat Completion ━━━"
echo "Sending: 'Merhaba, tek cümle ile kendini tanıt.'"
echo ""

RESPONSE=$(curl -s -X POST "$BASE_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "opencode/gpt-5-nano",
    "messages": [
      {"role": "user", "content": "Merhaba, tek cümle ile kendini tanıt."}
    ]
  }')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

# Yanıttan content'i çıkar
CONTENT=$(echo "$RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data['choices'][0]['message']['content'])
except:
    print('(yanıt ayrıştırılamadı)')
" 2>/dev/null)

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📝 Yanıt: $CONTENT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
