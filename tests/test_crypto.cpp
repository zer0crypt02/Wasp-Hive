// ============================================================================
// test_crypto.cpp — Unit tests for MWare/crypto.{h,cpp} (AEAD + file layer)
//
// test_kex.cpp covers the ECDH handshake primitives; this file covers the
// symmetric side that the ransomware GUI actually drives:
//
//   - ChaCha20 block function      RFC 8439 §2.3.2 vector
//   - ChaCha20-Poly1305 AEAD       round-trip, tag length, wrong key, tampering
//   - Nonce / per-file key         uniqueness, nonce size
//   - deriveKeyFromString()        deterministic, password-sensitive
//   - encryptTargetFile() /        the exact pair RansomwareFrame::AttemptUnlock
//     decryptTargetFile()          ends up calling (run in a temp dir)
//
// Build & run:  make test-crypto
// Exit:         0 = all assertions passed
// ============================================================================
#include "crypto.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <set>
#include <algorithm>

#include <unistd.h>     // chdir, dup, dup2, close
#include <dirent.h>     // counting files in the scratch dir

static int g_failures = 0;

// Single boolean assertion. Everything below funnels through this so the exit
// code is a single source of truth.
static void expectTrue(const char* name, bool cond) {
    if (!cond) {
        printf("FAIL %s\n", name);
        g_failures++;
    } else {
        printf("ok   %s\n", name);
    }
}

// Byte-exact comparison with a readable failure message.
static void expectBytes(const char* name, const std::vector<uint8_t>& got,
                        const std::vector<uint8_t>& want) {
    if (got != want) {
        printf("FAIL %s (got %zu bytes, want %zu, %s)\n",
               name, got.size(), want.size(),
               got.size() == want.size() ? "content differs" : "length differs");
        g_failures++;
    } else {
        printf("ok   %s\n", name);
    }
}

// Silence stdout while a function that prints progress unconditionally runs
// (encryptTargetFile/decryptTargetFile announce keys on the console).
struct StdoutMute {
    int saved;
    StdoutMute() {
        fflush(stdout);
        saved = dup(STDOUT_FILENO);
        FILE* null_out = freopen("/dev/null", "w", stdout);
        (void)null_out;
    }
    ~StdoutMute() {
        fflush(stdout);
        if (saved >= 0) {
            dup2(saved, STDOUT_FILENO);
            close(saved);
        }
    }
};

static bool readFileToString(const std::string& path, std::string* out) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out->append(buf, n);
    fclose(f);
    return true;
}

static bool fileExists(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    fclose(f);
    return true;
}

// ---- A. ChaCha20 block function (RFC 8439 §2.3.2) --------------------------
static void testChaCha20Block() {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;          // 00 01 02 .. 1f

    uint8_t nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0};
    uint8_t out[64];
    chacha20Block(key, 1, nonce, out);

    // First 8 bytes of the RFC's expected keystream block.
    static const uint8_t want[8] = {0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1};
    expectTrue("chacha20Block matches RFC 8439 vector", memcmp(out, want, 8) == 0);
}

// ---- B. AEAD: round-trip and every failure mode ----------------------------
static void testAead() {
    uint8_t key[32];
    deriveKeyFromString("WaspHive2024!", key);

    std::vector<uint8_t> pt;
    for (int i = 0; i < 1000; i++) pt.push_back((uint8_t)(i * 31 + 7));  // >3 blocks

    std::vector<uint8_t> nonce;
    for (int i = 0; i < 12; i++) nonce.push_back((uint8_t)(i + 1));

    std::vector<uint8_t> ct = chacha20Poly1305Encrypt(pt, key, nonce.data());
    expectTrue("encrypt appends a 16-byte Poly1305 tag",
               ct.size() == pt.size() + 16);
    expectTrue("ciphertext differs from plaintext", ct != pt);

    expectBytes("AEAD round-trip restores plaintext",
                chacha20Poly1305Decrypt(ct, key, nonce.data()), pt);

    // Wrong key must fail closed (empty), never return garbage that the caller
    // would happily write to disk as "decrypted".
    uint8_t wrong_key[32];
    deriveKeyFromString("WaspHive20241", wrong_key);   // the pre-fix '!' typo
    expectTrue("wrong key rejected",
               chacha20Poly1305Decrypt(ct, wrong_key, nonce.data()).empty());

    // A single flipped ciphertext bit must invalidate the whole message.
    std::vector<uint8_t> tampered_ct = ct;
    tampered_ct[10] ^= 0x01;
    expectTrue("tampered ciphertext rejected",
               chacha20Poly1305Decrypt(tampered_ct, key, nonce.data()).empty());

    // Same for the tag itself.
    std::vector<uint8_t> tampered_tag = ct;
    tampered_tag.back() ^= 0xFF;
    expectTrue("tampered tag rejected",
               chacha20Poly1305Decrypt(tampered_tag, key, nonce.data()).empty());

    // A different nonce must not decrypt the same blob.
    std::vector<uint8_t> other_nonce = nonce;
    other_nonce[0] ^= 0x01;
    expectTrue("wrong nonce rejected",
               chacha20Poly1305Decrypt(ct, key, other_nonce.data()).empty());

    // Empty input is legal and must survive the round-trip.
    std::vector<uint8_t> empty;
    std::vector<uint8_t> empty_ct = chacha20Poly1305Encrypt(empty, key, nonce.data());
    expectTrue("empty plaintext -> tag-only ciphertext (16 bytes)",
               empty_ct.size() == 16);
    expectBytes("empty plaintext round-trip",
                chacha20Poly1305Decrypt(empty_ct, key, nonce.data()), empty);
}

// ---- C. Nonce / key generation --------------------------------------------
static void testGenerators() {
    std::set<std::string> nonces;
    for (int i = 0; i < 200; i++) nonces.insert(generateNonce());
    expectTrue("200 generated nonces are all distinct", nonces.size() == 200);
    expectTrue("nonce is 12 bytes (ChaCha20-Poly1305 IETF)",
               generateNonce().size() == 12);

    std::set<std::string> keys;
    for (int i = 0; i < 200; i++) keys.insert(generateEncryptionKey());
    expectTrue("200 per-file keys are all distinct", keys.size() == 200);

    // The encrypted-extension must never be empty, or every encrypted file
    // would collide with its own plaintext name.
    expectTrue("encrypted extension is non-empty", !getEncryptedExt().empty());
}

// ---- D. Password -> key derivation ----------------------------------------
static void testDeriveKey() {
    uint8_t a[32], b[32], c[32];
    deriveKeyFromString("WaspHive2024!", a);
    deriveKeyFromString("WaspHive2024!", b);
    deriveKeyFromString("WaspHive2024?", c);   // one character off

    expectTrue("deriveKeyFromString is deterministic", memcmp(a, b, 32) == 0);
    expectTrue("deriveKeyFromString is password-sensitive", memcmp(a, c, 32) != 0);

    // A short password must still fill all 32 bytes (no zero padding tail).
    uint8_t short_key[32];
    memset(short_key, 0xAA, 32);
    deriveKeyFromString("x", short_key);
    uint8_t zeros[32] = {0};
    expectTrue("short password does not leave zero padding",
               memcmp(short_key + 16, zeros, 16) != 0);
}

// ---- E. File layer: encryptTargetFile / decryptTargetFile ------------------
// The GUI's unlock path calls exactly this pair, so it gets the real test.
// Runs inside a throwaway directory: the functions are hardcoded to "./target.txt".
static void testFileLayer() {
    char tmpl[] = "/tmp/mware_crypto_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) {
        printf("FAIL could not create scratch directory\n");
        g_failures++;
        return;
    }

    char original_cwd[4096];
    bool have_cwd = getcwd(original_cwd, sizeof(original_cwd)) != nullptr;
    if (chdir(dir) != 0) {
        printf("FAIL chdir into scratch directory\n");
        g_failures++;
        return;
    }

    const std::string enc_path = std::string("target.txt") + ENCRYPTED_EXT;
    bool ok = false;

    // 1st pass: no target.txt present -> encryptTargetFile must create the
    // default sample file, encrypt it, and delete the plaintext.
    {
        StdoutMute mute;
        ok = encryptTargetFile();
    }
    expectTrue("encryptTargetFile succeeds with no pre-existing target.txt", ok);
    expectTrue("plaintext target.txt removed after encryption",
               !fileExists("target.txt"));
    expectTrue("ciphertext file created", fileExists(enc_path));

    // 2nd pass: wrong password must fail AND leave the ciphertext in place,
    // otherwise the victim loses their data on a typo.
    {
        StdoutMute mute;
        ok = decryptTargetFile("wrong-password");
    }
    expectTrue("decryptTargetFile rejects a wrong password", !ok);
    expectTrue("ciphertext survives a failed unlock", fileExists(enc_path));
    expectTrue("no plaintext written on a failed unlock", !fileExists("target.txt"));

    // 3rd pass: the real password must restore byte-identical content.
    std::string before_unlock;
    {
        StdoutMute mute;
        ok = decryptTargetFile("WaspHive2024!");
    }
    expectTrue("decryptTargetFile accepts the correct password", ok);
    expectTrue("plaintext restored", fileExists("target.txt"));
    expectTrue("ciphertext removed after a successful unlock", !fileExists(enc_path));

    // The decrypted sample must be exactly the text encryptTargetFile writes.
    // (Same literal as crypto.cpp; the test pins the contract, so a change there
    // is a deliberate change here.)
    readFileToString("target.txt", &before_unlock);
    expectTrue("restored content is the original sample",
               before_unlock.find("WASP HIVE RANSOMWARE TEST FILE") == 0);

    // Round-trip in the other direction: encrypt an existing file and unlock it.
    {
        FILE* f = fopen("target.txt", "wb");
        const char* payload = "round-trip payload with non-ASCII: \xC3\xA7\xC4\x9F\xC3\xBC";
        if (f) { fwrite(payload, 1, strlen(payload), f); fclose(f); }
    }
    {
        StdoutMute mute;
        ok = encryptTargetFile();
    }
    expectTrue("re-encrypt of an existing target.txt succeeds", ok);
    {
        StdoutMute mute;
        ok = decryptTargetFile("WaspHive2024!");
    }
    std::string after;
    readFileToString("target.txt", &after);
    expectTrue("second round-trip restores the custom payload",
               ok && after == "round-trip payload with non-ASCII: \xC3\xA7\xC4\x9F\xC3\xBC");

    // Restore the caller's working directory before cleaning up.
    if (have_cwd) {
        char cmd[4300];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
        if (chdir(original_cwd) == 0) {
            if (system(cmd) != 0) { /* best effort */ }
        }
    }
}

int main() {
    testChaCha20Block();
    testAead();
    testGenerators();
    testDeriveKey();
    testFileLayer();

    if (g_failures == 0) {
        printf("\nALL TESTS PASSED\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED\n", g_failures);
    return 1;
}
