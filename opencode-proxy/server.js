#!/usr/bin/env node
/**
 * OpenCode HTTP API Proxy Server
 *
 * Accepts OpenAI-compatible POST /v1/chat/completions requests
 * and forwards them to OpenCode CLI via `opencode run --format json`.
 * Designed for Termux on Android (ARM64).
 *
 * Usage:
 *   node server.js [--port 3001] [--opencode /path/to/opencode]
 *
 * Endpoints:
 *   POST /v1/chat/completions  - OpenAI-compatible chat completions
 *   GET  /v1/models            - List available models
 *   GET  /health               - Health check
 */

const http = require("http");
const { spawn, execSync } = require("child_process");
const path = require("path");
const net = require("net");
const fs = require("fs");

// ─── Config ──────────────────────────────────────────────────────
const START_PORT = parseInt(process.env.PORT || "3001", 10);
const OPENCODE_BIN =
  process.env.OPENCODE_BIN || "/sdcard/opencode";
const HOST = "0.0.0.0";

// Default model - adjusts based on v0.0.55 vs newer
const DEFAULT_MODEL = process.env.DEFAULT_MODEL || "opencode/gpt-5-nano";
const FALLBACK_MODEL = "copilot.gpt-4o";

// ─── Instance Tracking ───────────────────────────────────────────
// Tüm çalışan instance'ları /tmp/freebuff-instances.json dosyasında takip eder
const INSTANCES_FILE = "/tmp/freebuff-instances.json";
const INSTANCE_ID = `freebuff-${process.pid}-${Date.now()}`;

function getRunningInstances() {
  try {
    if (fs.existsSync(INSTANCES_FILE)) {
      const data = JSON.parse(fs.readFileSync(INSTANCES_FILE, "utf8"));
      // Sadece yaşayan process'leri filtrele (zombie'ları temizle)
      return data.filter((inst) => {
        try {
          process.kill(inst.pid, 0); //kill 0 = sadece varlığını kontrol et
          return true;
        } catch (_) {
          return false; // process yoksa listden çıkar
        }
      });
    }
  } catch (_) {}
  return [];
}

function registerInstance(port) {
  const instances = getRunningInstances();
  instances.push({
    pid: process.pid,
    port: port,
    id: INSTANCE_ID,
    startedAt: new Date().toISOString(),
    model: DEFAULT_MODEL,
  });
  fs.writeFileSync(INSTANCES_FILE, JSON.stringify(instances, null, 2));
}

function unregisterInstance() {
  try {
    const instances = getRunningInstances().filter(
      (inst) => inst.pid !== process.pid
    );
    fs.writeFileSync(INSTANCES_FILE, JSON.stringify(instances, null, 2));
  } catch (_) {}
}

/**
 * Otomatik boş port bul.
 * START_PORT'tan başlayarak einseria (port 3001 → 3002 → 3003 ...)
 */
function findAvailablePort(startPort) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", () => {
      // Port meşgul → bir sonrakini dene
      findAvailablePort(startPort + 1).then(resolve, reject);
    });
    server.listen(startPort, HOST, () => {
      server.close(() => resolve(startPort));
    });
  });
}

// ─── Helpers ─────────────────────────────────────────────────────

/**
 * Extract the last user message content from OpenAI messages array.
 * Supports both string content and array content (with text parts).
 */
function extractUserMessage(messages) {
  if (!Array.isArray(messages) || messages.length === 0) {
    return null;
  }
  // Walk backwards to find last user message
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg.role === "user") {
      if (typeof msg.content === "string") {
        return msg.content;
      }
      if (Array.isArray(msg.content)) {
        // Extract text parts from content array
        const textParts = msg.content
          .filter((p) => p.type === "text")
          .map((p) => p.text);
        return textParts.join("\n") || null;
      }
    }
  }
  return null;
}

/**
 * Build system prompt from messages (all system messages concatenated).
 */
function buildSystemPrompt(messages) {
  if (!Array.isArray(messages)) return "";
  return messages
    .filter((m) => m.role === "system")
    .map((m) => (typeof m.content === "string" ? m.content : ""))
    .join("\n\n");
}

/**
 * Parse OpenCode JSONL output and extract the final text response + usage.
 * Each line is a JSON object with a "type" field.
 */
function parseOpenCodeOutput(jsonl) {
  const lines = jsonl.split("\n").filter((l) => l.trim());
  let text = "";
  let usage = { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };

  for (const line of lines) {
    try {
      const event = JSON.parse(line);
      switch (event.type) {
        case "text":
          // Accumulate text from model responses
          if (event.part && event.part.text) {
            text += event.part.text;
          }
          break;
        case "step_finish":
          // Extract token usage from the final step
          if (event.part && event.part.tokens) {
            const t = event.part.tokens;
            usage.prompt_tokens = t.input || 0;
            usage.completion_tokens = t.output || 0;
            usage.total_tokens =
              usage.prompt_tokens + usage.completion_tokens;
          }
          break;
        case "error":
          // Capture error info
          const errMsg =
            event.error?.data?.message || event.error?.name || "Unknown error";
          throw new Error(`OpenCode error: ${errMsg}`);
        // Other event types (step_start, tool_use) are ignored for response
      }
    } catch (e) {
      if (e.message.startsWith("OpenCode error:")) throw e;
      // Skip unparseable lines
    }
  }

  return { text, usage };
}

/**
 * Generate a unique ID for OpenAI-compatible responses.
 */
function generateId() {
  return "chatcmpl-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

/**
 * Run opencode CLI and return parsed output.
 * Uses `opencode run "prompt" --format json` for non-interactive mode.
 */
function runOpenCode(prompt, model) {
  return new Promise((resolve, reject) => {
    const args = ["run"];

    // Model argümanı (eğer belirtilmişse)
    if (model && model !== DEFAULT_MODEL) {
      args.push("--model", model);
    }

    // Prompt
    args.push(prompt);

    // JSON format output (JSONL - one JSON object per line)
    args.push("--format", "json");

    // opencode-termux binary'si için ortam değişkenleri
    const prefixBin = "/data/data/com.termux/files/usr/bin";
    const prefixLib = "/data/data/com.termux/files/usr/lib";
    const existingLd = process.env.LD_LIBRARY_PATH || "";

    // opencode-termux: opencode bir wrapper script, asıl binary opencode.bin
    // Doğrudan .bin çağrılırsa opentui hatası azalır
    let binPath = OPENCODE_BIN;
    let binArgs = args;
    const binFile = OPENCODE_BIN + ".bin";
    try {
      const fs = require("fs");
      if (fs.existsSync(binFile)) {
        binPath = binFile;
        // .bin argsları farklı olabilir, --clean veya --no-tui ekle
        binArgs = ["--no-tui", ...args];
      }
    } catch (_) {}

    const proc = spawn(binPath, binArgs, {
      cwd: "/data/data/com.termux/files/home",
      env: {
        ...process.env,
        HOME: "/data/data/com.termux/files/home",
        PREFIX: "/data/data/com.termux/files/usr",
        TMPDIR: process.env.TMPDIR || "/data/data/com.termux/files/usr/tmp",
        PATH: `${prefixBin}:${process.env.PATH || "/usr/bin:/bin"}`,
        LD_LIBRARY_PATH: [prefixLib, existingLd].filter(Boolean).join(":"),
        OPENTUI_LIB_PATH: `${prefixLib}/libopentui.so`,
        // TUI'yi devre dışı bırak (non-interactive mod)
        BUN_PTY_LIB: "0",
        OPENTUI_DISABLE: "1",
        // Non-interactive mode
        NO_COLOR: "1",
        TERM: "dumb",
        FORCE_COLOR: "0",
      },
      stdio: ["pipe", "pipe", "pipe"],
      // 90 saniye timeout (büyük promptlar için)
      timeout: 90000,
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.on("close", (code) => {
      if (code !== 0 && !stdout.trim()) {
        reject(
          new Error(
            `OpenCode exited with code ${code}: ${stderr.slice(0, 500)}`
          )
        );
        return;
      }
      try {
        const result = parseOpenCodeOutput(stdout);
        resolve(result);
      } catch (e) {
        reject(e);
      }
    });

    proc.on("error", (err) => {
      reject(new Error(`Failed to spawn opencode: ${err.message}`));
    });
  });
}

// ─── HTTP Server ─────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  // CORS headers (aynı WiFi'den erişim için)
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // Preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  // ── GET /health ──
  if (req.method === "GET" && url.pathname === "/health") {
    // OpenCode binary'sinin çalışıp çalışmadığını kontrol et
    let opencodeOk = false;
    try {
      execSync(`${OPENCODE_BIN} --version`, {
        timeout: 5000,
        stdio: "pipe",
      });
      opencodeOk = true;
    } catch (_) {}

    res.writeHead(opencodeOk ? 200 : 503, {
      "Content-Type": "application/json",
    });
    res.end(
      JSON.stringify({
        status: opencodeOk ? "ok" : "degraded",
        instance_id: INSTANCE_ID,
        pid: process.pid,
        opencode_binary: OPENCODE_BIN,
        opencode_available: opencodeOk,
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
      })
    );
    return;
  }

  // ── GET /instances ──
  // Tüm çalışan Freebuff instance'larını listeler
  if (req.method === "GET" && url.pathname === "/instances") {
    const instances = getRunningInstances();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        total: instances.length,
        current: { pid: process.pid, port: PORT || START_PORT, id: INSTANCE_ID },
        instances: instances,
      })
    );
    return;
  }

  // ── GET /v1/models ──
  if (req.method === "GET" && url.pathname === "/v1/models") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        object: "list",
        data: [
          {
            id: DEFAULT_MODEL,
            object: "model",
            created: Math.floor(Date.now() / 1000),
            owned_by: "opencode",
          },
          {
            id: FALLBACK_MODEL,
            object: "model",
            created: Math.floor(Date.now() / 1000),
            owned_by: "opencode",
          },
          {
            id: "opencode/big-pickle",
            object: "model",
            created: Math.floor(Date.now() / 1000),
            owned_by: "opencode",
          },
          {
            id: "opencode/mimo-v2-omni-free",
            object: "model",
            created: Math.floor(Date.now() / 1000),
            owned_by: "opencode",
          },
        ],
      })
    );
    return;
  }

  // ── POST /v1/chat/completions ──
  if (req.method === "POST" && url.pathname === "/v1/chat/completions") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const request = JSON.parse(body);
        const messages = request.messages || [];
        const model = request.model || DEFAULT_MODEL;
        const stream = request.stream || false;

        // System prompt'u mesajlardan çıkar
        const systemPrompt = buildSystemPrompt(messages);
        // Son user mesajını al
        const userMessage = extractUserMessage(messages);

        if (!userMessage) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: {
                message: "No user message found in messages array",
                type: "invalid_request_error",
                code: "missing_user_message",
              },
            })
          );
          return;
        }

        // System prompt varsa user mesajına ekle
        const fullPrompt = systemPrompt
          ? `[System Instructions]\n${systemPrompt}\n\n[User Request]\n${userMessage}`
          : userMessage;

        console.log(
          `[${new Date().toISOString()}] Incoming request: model=${model}, prompt_len=${fullPrompt.length}`
        );

        // Streaming modunda SSE formatında yanıt ver
        if (stream) {
          res.writeHead(200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
          });

          const chatId = generateId();
          const sendSSE = (data) => {
            res.write(`data: ${JSON.stringify(data)}\n\n`);
          };

          try {
            // İlk chunk: role bilgisi
            sendSSE({
              id: chatId,
              object: "chat.completion.chunk",
              created: Math.floor(Date.now() / 1000),
              model: model,
              choices: [
                {
                  index: 0,
                  delta: { role: "assistant", content: "" },
                  finish_reason: null,
                },
              ],
            });

            const result = await runOpenCode(fullPrompt, model);

            // Text chunk'larınısstream olarak gönder
            if (result.text) {
              // Metni küçük parçalara böl (streaming efekti için)
              const chunkSize = 50;
              for (let i = 0; i < result.text.length; i += chunkSize) {
                sendSSE({
                  id: chatId,
                  object: "chat.completion.chunk",
                  created: Math.floor(Date.now() / 1000),
                  model: model,
                  choices: [
                    {
                      index: 0,
                      delta: { content: result.text.slice(i, i + chunkSize) },
                      finish_reason: null,
                    },
                  ],
                });
              }
            }

            // Finish
            sendSSE({
              id: chatId,
              object: "chat.completion.chunk",
              created: Math.floor(Date.now() / 1000),
              model: model,
              choices: [
                {
                  index: 0,
                  delta: {},
                  finish_reason: "stop",
                },
              ],
              usage: result.usage,
            });

            res.write("data: [DONE]\n\n");
            res.end();
          } catch (err) {
            console.error(`[${new Date().toISOString()}] OpenCode error:`, err.message);
            sendSSE({
              id: chatId,
              object: "chat.completion.chunk",
              created: Math.floor(Date.now() / 1000),
              model: model,
              choices: [
                {
                  index: 0,
                  delta: { content: `[Error: ${err.message}]` },
                  finish_reason: "stop",
                },
              ],
            });
            res.write("data: [DONE]\n\n");
            res.end();
          }
          return;
        }

        // Non-streaming mod (normal JSON yanıt)
        const result = await runOpenCode(fullPrompt, model);

        console.log(
          `[${new Date().toISOString()}] Response: ${result.text.length} chars, ${result.usage.total_tokens} tokens`
        );

        const response = {
          id: generateId(),
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: model,
          choices: [
            {
              index: 0,
              message: {
                role: "assistant",
                content: result.text || "(No response from OpenCode)",
              },
              finish_reason: "stop",
            },
          ],
          usage: result.usage,
        };

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(response));
      } catch (err) {
        console.error(
          `[${new Date().toISOString()}] Request error:`,
          err.message
        );
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: {
              message: err.message,
              type: "server_error",
              code: "opencode_error",
            },
          })
        );
      }
    });
    return;
  }

  // ── 404 ──
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(
    JSON.stringify({
      error: {
        message: `Unknown endpoint: ${req.method} ${url.pathname}`,
        type: "invalid_request_error",
      },
    })
  );
});

// ─── Start ───────────────────────────────────────────────────────
// Dinamik port bul: 3001 meşgulse → 3002 → 3003 → ... (sınırsız instance)
let PORT;

findAvailablePort(START_PORT)
  .then((port) => {
    PORT = port;
    // Instance'ı kaydet (diğer instance'lar görsün)
    registerInstance(PORT);

    server.listen(PORT, HOST, () => {
      const localIP = getLocalIP();
      const instances = getRunningInstances();
      console.log(`
╔══════════════════════════════════════════════════════╗
║      Freebuff API Proxy — Multi-Instance v2.0       ║
╠══════════════════════════════════════════════════════╣
║  🔥 Instance: #${String(instances.length).padEnd(3)} (PID: ${String(process.pid).padEnd(6)})             ║
║  🌐 Port: ${String(PORT).padEnd(5)}  |  Model: ${DEFAULT_MODEL.padEnd(20)}  ║
║                                                      ║
║  Endpoints:                                          ║
║    POST /v1/chat/completions  (OpenAI format)       ║
║    GET  /v1/models                                  ║
║    GET  /health    → bu instance bilgisi             ║
║    GET  /instances → tüm çalışan instance'lar        ║
║                                                      ║
║  📱 Same WiFi:                                      ║
║    http://${localIP}:${PORT}                           ║
║                                                      ║
║  💡 Yeni terminalde aç:                              ║
║    node server.js          (otomatik port bulur)     ║
║    PORT=3005 node server.js (manuel port)            ║
╚══════════════════════════════════════════════════════╝

  Aktif instance'lar (${instances.length} adet):
${instances.map((i) => `    → Port ${i.port} (PID ${i.pid}) ${i.id === INSTANCE_ID ? '← BU' : ''}`).join("\n")}
`);
    });
  })
  .catch((err) => {
    console.error(`❌ Kullanılabilir port bulunamadı: ${err.message}`);
    process.exit(1);
  });

/**
 * Get local WiFi IP address for LAN access.
 */
function getLocalIP() {
  const { networkInterfaces } = require("os");
  const nets = networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === "IPv4" && !net.internal) {
        return net.address;
      }
    }
  }
  return "127.0.0.1";
}

// Graceful shutdown — instance'ı listeden temizle
process.on("SIGINT", () => {
  console.log("\n[Server] Kapatılıyor...");
  unregisterInstance();
  server.close(() => process.exit(0));
});
process.on("SIGTERM", () => {
  unregisterInstance();
  server.close(() => process.exit(0));
});
process.on("exit", () => {
  unregisterInstance();
});
