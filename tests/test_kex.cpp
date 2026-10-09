// ============================================================================
// test_kex.cpp — Unit tests for MWare/keyexchange.{h,cpp}
//
// Vectors:
//   - SHA-256: FIPS 180-4 ("", "abc")
//   - HMAC-SHA256: RFC 4231 test case 1
//   - HKDF-SHA256: RFC 5869 appendix A.1
//   - X25519: RFC 7748 §5.2 (both vectors) + DH agreement
//
// Build & run:  make test-kex
// ============================================================================
#include "../MWare/keyexchange.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_failures = 0;

static void expectHex(const char* name, const uint8_t* got, size_t len,
                      const char* want_hex) {
    std::string hex;
    static const char* d = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex += d[got[i] >> 4];
        hex += d[got[i] & 0xF];
    }
    if (hex != want_hex) {
        printf("FAIL %s\n  got  %s\n  want %s\n", name, hex.c_str(), want_hex);
        g_failures++;
    } else {
        printf("ok   %s\n", name);
    }
}

static std::vector<uint8_t> unhex(const char* h) {
    std::vector<uint8_t> out;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; h[i] && h[i+1]; i += 2)
        out.push_back((uint8_t)((val(h[i]) << 4) | val(h[i+1])));
    return out;
}

int main() {
    // ---- SHA-256 (FIPS 180-4) ----
    uint8_t d[32];
    sha256((const uint8_t*)"", 0, d);
    expectHex("sha256(\"\")", d, 32,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    sha256((const uint8_t*)"abc", 3, d);
    expectHex("sha256(\"abc\")", d, 32,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // ---- HMAC-SHA256 (RFC 4231 case 1) ----
    uint8_t key1[20];
    memset(key1, 0x0b, 20);
    hmacSha256(key1, 20, (const uint8_t*)"Hi There", 8, d);
    expectHex("hmac-sha256 rfc4231#1", d, 32,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    // ---- HKDF-SHA256 (RFC 5869 A.1) ----
    {
        auto ikm  = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        auto salt = unhex("000102030405060708090a0b0c");
        auto info = unhex("f0f1f2f3f4f5f6f7f8f9");
        uint8_t prk[32], okm[42];

        // PRK check via HMAC directly (extract step)
        hmacSha256(salt.data(), salt.size(), ikm.data(), ikm.size(), prk);
        expectHex("hkdf-extract prk", prk, 32,
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5");

        hkdfSha256(ikm.data(), ikm.size(), salt.data(), salt.size(),
                   info.data(), info.size(), okm, 42);
        expectHex("hkdf-expand okm", okm, 42,
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865");
    }

    // ---- X25519 (RFC 7748 §5.2) ----
    {
        auto sc = unhex("a546e36bf0527c9d3b16154b82465edd"
                         "62144c0ac1fc5a18506a2244ba449ac4");
        auto u  = unhex("e6db6867583030db3594c1a424b15f7c"
                         "726624ec26b3353b10a903a6d0ab1c4c");
        uint8_t out[32];
        x25519(out, sc.data(), u.data());
        expectHex("x25519 rfc7748#1", out, 32,
            "c3da55379de9c6908e94ea4df28d084f"
            "32eccf03491c71f754b4075577a28552");
    }
    {
        auto sc = unhex("4b66e9d4d1b4673c5ad22691957d6af5"
                         "c11b6421e0ea01d42ca4169e7918ba0d");
        auto u  = unhex("e5210f12786811d3f4b7959d0538ae2c"
                         "31dbe7106fc03c3efc4cd549c715a493");
        uint8_t out[32];
        x25519(out, sc.data(), u.data());
        expectHex("x25519 rfc7748#2", out, 32,
            "95cbde9476e8907d7aade45cb4b873f8"
            "8b595a68799fa152e6f8f7647aac7957");
    }

    // ---- DH agreement both directions ----
    {
        uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32];
        if (x25519Keypair(a_priv, a_pub) != 0 ||
            x25519Keypair(b_priv, b_pub) != 0) {
            printf("FAIL keypair generation (CSPRNG)\n");
            g_failures++;
        } else {
            uint8_t s1[32], s2[32];
            x25519(s1, a_priv, b_pub);
            x25519(s2, b_priv, a_pub);
            if (memcmp(s1, s2, 32) != 0) {
                printf("FAIL dh agreement: shared secrets differ\n");
                g_failures++;
            } else {
                printf("ok   dh agreement (both directions match)\n");
            }
            // Negative control: a's own keypair must NOT produce the shared secret
            uint8_t wrong[32];
            x25519(wrong, a_priv, a_pub);
            if (memcmp(s1, wrong, 32) == 0) {
                printf("FAIL dh negative control\n");
                g_failures++;
            } else {
                printf("ok   dh negative control\n");
            }
        }
    }

    // ---- Handshake helper consistency: both sides derive same session key ----
    {
        uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32];
        x25519Keypair(a_priv, a_pub);   // "server"
        x25519Keypair(b_priv, b_pub);   // "bot"
        uint8_t shared_s[32], shared_b[32];
        x25519(shared_s, a_priv, b_pub);
        x25519(shared_b, b_priv, a_pub);

        std::string bot_id = "MAC_A1B2C3";
        uint8_t k1[32], k2[32];
        deriveSessionKey(shared_s, a_pub, b_pub, bot_id, k1);
        deriveSessionKey(shared_b, a_pub, b_pub, bot_id, k2);
        if (memcmp(k1, k2, 32) != 0) {
            printf("FAIL session key mismatch between sides\n");
            g_failures++;
        } else {
            printf("ok   session key agreement\n");
        }

        // Wrong bot_id must yield a different key (transcript binding)
        uint8_t k3[32];
        deriveSessionKey(shared_s, a_pub, b_pub, "MAC_EVIL", k3);
        if (memcmp(k1, k3, 32) == 0) {
            printf("FAIL transcript binding (bot_id not mixed in)\n");
            g_failures++;
        } else {
            printf("ok   transcript binding (bot_id mixed in)\n");
        }

        // Mutual auth MACs agree + wrong PSK fails
        std::string psk = "correct horse battery staple";
        uint8_t mac_s[32], mac_b[32];
        computeAuthMac(psk, a_pub, b_pub, bot_id, mac_s);
        computeAuthMac(psk, a_pub, b_pub, bot_id, mac_b);
        if (!constantTimeEqual(mac_s, mac_b, 32)) {
            printf("FAIL auth mac mismatch\n");
            g_failures++;
        } else {
            printf("ok   auth mac agreement\n");
        }
        uint8_t mac_bad[32];
        computeAuthMac("wrong psk", a_pub, b_pub, bot_id, mac_bad);
        if (constantTimeEqual(mac_s, mac_bad, 32)) {
            printf("FAIL auth mac wrong-psk accepted\n");
            g_failures++;
        } else {
            printf("ok   auth mac rejects wrong psk\n");
        }

        uint8_t c1[32], c2[32];
        computeConfirmMac(psk, a_pub, b_pub, c1);
        computeConfirmMac(psk, a_pub, b_pub, c2);
        if (!constantTimeEqual(c1, c2, 32)) {
            printf("FAIL confirm mac mismatch\n");
            g_failures++;
        } else {
            printf("ok   confirm mac agreement\n");
        }
    }

    if (g_failures) {
        printf("\n%d FAILURE(S)\n", g_failures);
        return 1;
    }
    printf("\nALL TESTS PASSED\n");
    return 0;
}
