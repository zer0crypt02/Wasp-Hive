# OpenCode API Proxy — Termux (Android)

OpenCode CLI'ı HTTP API proxy'ye çevirir. Bilgisayar veya başka bir cihazdan
aynı WiFi ağı üzerinden OpenAI-Formatında istek gönderebilirsiniz.

## Hızlı Kurulum (Termux)

```bash
# 1. Dosyaları telefonuna kopyala
# (Bilgisayarından Termux'a)
scp -r opencode-proxy/ phone:~/

# 2. Termux'ta kur
cd ~/opencode-proxy
bash setup.sh

# 3. Başlat
bash start.sh
```

## v0.0.55 Hatası: "agent coder not found"

### Sebep

v0.0.55 Go binary'sinde `coder` agent'ı config'de model ataması olmadan
çalışmaz. Ayrıca `opencode/gpt-5-nano` modeli bu versiyonda mevcut değil.

### Çözüm 1: v0.0.55 ile Çalışmak (Önerilen)

Config dosyasını `~/.config/opencode/opencode.json`'a koy:

```json
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
  "autoCompact": true
}
```

> **Not:** `copilot.gpt-4o` GitHub Copilot aboneliği gerektirir.
> Aboneliğiniz yoksa OpenAI API key ile `gpt-4o` kullanın:
> ```json
> "agents": {
>   "coder": { "model": "gpt-4o", "maxTokens": 16384 }
> }
> ```
> ve `OPENAI_API_KEY`环境変数ını ayarlayın.

### Çözüm 2: Yeni Versiyon Kurmak

```bash
# npm ile son versiyonu kur
npm install -g opencode-ai

# veya curl ile
curl -fsSL https://opencode.ai/install | bash

# Sonra config:
mkdir -p ~/.config/opencode
cat > ~/.config/opencode/opencode.json << 'EOF'
{
  "model": "opencode/gpt-5-nano",
  "default_agent": "build"
}
EOF
```

> **Not:** npm sürümü Node.js gerektirir, ARM64 Termux'ta çalışır.
> curl ile kurulan binary glibc gerektirir, Termux'ta **çalışmaz**!
> opencode-termux projesini kullanın: https://github.com/guysoft/opencode-termux

## API Kullanımı

### Health Check
```bash
curl http://localhost:3001/health
```

### Models
```bash
curl http://localhost:3001/v1/models
```

### Chat Completions (Non-Streaming)
```bash
curl -X POST http://localhost:3001/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "opencode/gpt-5-nano",
    "messages": [
      {"role": "system", "content": "Sen yardımcı bir asistansın."},
      {"role": "user", "content": "Merhaba, Python ile HTTP server nasıl yazılır?"}
    ]
  }'
```

### Chat Completions (Streaming - SSE)
```bash
curl -X POST http://localhost:3001/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "opencode/gpt-5-nano",
    "messages": [
      {"role": "user", "content": "Hello world yaz Python'da"}
    ],
    "stream": true
  }'
```

### Bilgisayarından Erişim (Aynı WiFi)

1. Telefonun IP adresini bul:
   ```bash
   # Termux'ta
   hostname -I
   # veya
   ifconfig wlan0
   ```

2. Bilgisayarından:
   ```bash
   export OPENCODE_PROXY="http://192.168.x.x:3001"
   curl "$OPENCODE_PROXY/health"

   curl -X POST "$OPENCODE_PROXY/v1/chat/completions" \
     -H "Content-Type: application/json" \
     -d '{"messages":[{"role":"user","content":"test"}]}'
   ```

## Ortam Değişkenleri

| Değişken | Varsayılan | Açıklama |
|----------|------------|----------|
| `PORT` | `3001` | Dinlenecek port |
| `OPENCODE_BIN` | `/sdcard/opencode` | OpenCode binary yolu |
| `DEFAULT_MODEL` | `opencode/gpt-5-nano` | Varsayılan model |
| `OPENCODE_CONFIG` | — | Özel config dosya yolu |

## Mevcut Modeller (v0.0.55)

| Model ID | Ücretsiz? | Not |
|----------|-----------|-----|
| `copilot.gpt-4o` | Copilot aboneliği ile | Önerilen |
| `copilot.gpt-4o-mini` | Copilot aboneliği ile | Hafif görevler |
| `copilot.claude-3.7-sonnet` | Copilot aboneliği ile | Kod analizi |
| `gpt-4o` | API key gerekli | OpenAI |
| `gpt-4o-mini` | API key gerekli | Ucuz alternatif |

## Sorun Giderme

### "agent coder not found" hatası
→ Config'de `agents.coder.model` ayarla (yukarıya bak)

### OpenCode binary çalışmıyor (Termux)
→ Glibc-linked binary Termux'ta çalışmaz. npm sürümü kullanın:
```bash
npm install -g opencode-ai
export OPENCODE_BIN="$(which opencode)"
```

### Connection refused
→ Port 3001'de bir şey çalışıyor mu?
```bash
netstat -tlnp | grep 3001
```

### JSON parse hatası
→ OpenCode'nin stdout'u beklenmedik çıktı içeriyor.
Debug modu: `DEBUG=1 node server.js`

## Mimari

```
Bilgisayar/Client
    │
    │  POST /v1/chat/completions
    │  (OpenAI Format)
    ▼
┌─────────────────────┐
│   Node.js Proxy     │  ← server.js (port 3001)
│   (0.0.0.0:3001)    │
└─────────┬───────────┘
          │
          │  opencode run "prompt" --format json
          ▼
┌─────────────────────┐
│   OpenCode CLI      │  ← /sdcard/opencode
│   (Go Binary)       │
└─────────┬───────────┘
          │
          │  LLM API çağrısı
          ▼
┌─────────────────────┐
│   AI Provider       │  ← OpenCode Zen / OpenAI / Copilot
│   (Cloud)           │
└─────────────────────┘
```
