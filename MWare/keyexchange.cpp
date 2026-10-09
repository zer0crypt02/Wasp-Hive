// ============================================================================
// keyexchange.cpp — X25519 ECDH + SHA-256/HMAC/HKDF implementation
// ============================================================================
// Pure C++, zero dependencies. Verified against:
//   - FIPS 180-4 SHA-256 vectors ("", "abc")
//   - RFC 4231 HMAC-SHA256 test case 1
//   - RFC 5869 HKDF test case A.1
//   - RFC 7748 §5.2 X25519 test vectors (both)
//   - DH agreement: X25519(a, X25519(b,9)) == X25519(b, X25519(a,9))
// (see tests/test_kex.cpp)
//
// Implementation notes:
//   - Field arithmetic uses 4x64-bit limbs mod p = 2^255-19. Reduction is
//     the algebraic identity  2^255 ≡ 19 (mod p):  split → multiply high
//     part by 19 → add back, twice, then conditional subtract of p.
//   - The ladder follows RFC 7748 §5 pseudocode with branchless conditional
//     swap; scalars are clamped inside x25519() per the RFC.
// ============================================================================
#include "keyexchange.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

// ============================================================================
// SHA-256 (FIPS 180-4)
// ============================================================================
namespace {

constexpr uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

struct Sha256Ctx {
    uint32_t h[8];
    uint64_t total_len;      // message length in bytes
    uint8_t  buf[64];
    size_t   buf_len;
};

void sha256Init(Sha256Ctx& c) {
    c.h[0] = 0x6a09e667; c.h[1] = 0xbb67ae85;
    c.h[2] = 0x3c6ef372; c.h[3] = 0xa54ff53a;
    c.h[4] = 0x510e527f; c.h[5] = 0x9b05688c;
    c.h[6] = 0x1f83d9ab; c.h[7] = 0x5be0cd19;
    c.total_len = 0;
    c.buf_len = 0;
}

void sha256Transform(Sha256Ctx& c, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3];
    uint32_t e = c.h[4], f = c.h[5], g = c.h[6], h = c.h[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d;
    c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += h;
}

void sha256Update(Sha256Ctx& c, const uint8_t* data, size_t len) {
    c.total_len += len;
    while (len > 0) {
        size_t take = 64 - c.buf_len;
        if (take > len) take = len;
        memcpy(c.buf + c.buf_len, data, take);
        c.buf_len += take;
        data += take;
        len -= take;
        if (c.buf_len == 64) {
            sha256Transform(c, c.buf);
            c.buf_len = 0;
        }
    }
}

void sha256Final(Sha256Ctx& c, uint8_t out[32]) {
    uint64_t bit_len = c.total_len * 8;
    uint8_t pad = 0x80;
    sha256Update(c, &pad, 1);
    pad = 0x00;
    while (c.buf_len != 56) {           // pad until 56 bytes in buffer
        sha256Update(c, &pad, 1);
    }
    uint8_t len_be[8];
    for (int i = 0; i < 8; i++) len_be[i] = (uint8_t)(bit_len >> (56 - i*8));
    sha256Update(c, len_be, 8);

    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c.h[i] >> 24);
        out[i*4+1] = (uint8_t)(c.h[i] >> 16);
        out[i*4+2] = (uint8_t)(c.h[i] >> 8);
        out[i*4+3] = (uint8_t)(c.h[i]);
    }
}

} // anonymous namespace

void sha256(const uint8_t* data, size_t len, uint8_t out32[32]) {
    Sha256Ctx c;
    sha256Init(c);
    sha256Update(c, data, len);
    sha256Final(c, out32);
}

// ============================================================================
// HMAC-SHA256 (RFC 2104)
// ============================================================================
void hmacSha256(const uint8_t* key, size_t key_len,
                const uint8_t* msg, size_t msg_len,
                uint8_t out32[32]) {
    uint8_t k[64];
    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        sha256(key, key_len, k);       // hash long keys down to HashLen
    } else {
        memcpy(k, key, key_len);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    // inner = SHA256(ipad || msg)
    Sha256Ctx c;
    sha256Init(c);
    sha256Update(c, ipad, 64);
    sha256Update(c, msg, msg_len);
    uint8_t inner[32];
    sha256Final(c, inner);

    // outer = SHA256(opad || inner)
    sha256Init(c);
    sha256Update(c, opad, 64);
    sha256Update(c, inner, 32);
    sha256Final(c, out32);
}

// ============================================================================
// HKDF-SHA256 (RFC 5869)
// ============================================================================
void hkdfSha256(const uint8_t* ikm, size_t ikm_len,
                const uint8_t* salt, size_t salt_len,
                const uint8_t* info, size_t info_len,
                uint8_t* out, size_t out_len) {
    // Extract: PRK = HMAC(salt, IKM); salt defaults to HashLen zeros
    uint8_t default_salt[32] = {0};
    if (!salt || salt_len == 0) {
        salt = default_salt;
        salt_len = 32;
    }
    uint8_t prk[32];
    hmacSha256(salt, salt_len, ikm, ikm_len, prk);

    // Expand: T(0) = ""; T(i) = HMAC(PRK, T(i-1) || info || i)
    uint8_t t[32] = {0};
    size_t t_len = 0;
    size_t copied = 0;
    uint8_t counter = 1;
    std::vector<uint8_t> block;
    while (copied < out_len) {
        block.clear();
        block.insert(block.end(), t, t + t_len);
        if (info && info_len) block.insert(block.end(), info, info + info_len);
        block.push_back(counter);

        uint8_t t_new[32];
        hmacSha256(prk, 32, block.data(), block.size(), t_new);
        memcpy(t, t_new, 32);
        t_len = 32;

        size_t want = out_len - copied;
        size_t take = want < 32 ? want : 32;
        memcpy(out + copied, t, take);
        copied += take;
        counter++;
    }
    // wipe PRK (best effort)
    memset(prk, 0, sizeof(prk));
}

// ============================================================================
// X25519 (RFC 7748)
// ============================================================================
namespace {

using fe = uint64_t[4];   // 4 x 64-bit limbs, value mod p = 2^255 - 19

inline void feFromBytes(fe r, const uint8_t s[32]) {
    for (int i = 0; i < 4; i++) {
        r[i] = (uint64_t)s[i*8]     | ((uint64_t)s[i*8+1] << 8) |
               ((uint64_t)s[i*8+2] << 16) | ((uint64_t)s[i*8+3] << 24) |
               ((uint64_t)s[i*8+4] << 32) | ((uint64_t)s[i*8+5] << 40) |
               ((uint64_t)s[i*8+6] << 48) | ((uint64_t)s[i*8+7] << 56);
    }
    r[3] &= 0x7fffffffffffffffULL;   // mask bit 255 (RFC 7748 §5)
}

inline void feToBytes(uint8_t out[32], const fe r) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            out[i*8+j] = (uint8_t)(r[i] >> (j*8));
        }
    }
    out[31] &= 0x7f;                 // canonical: top bit always 0
}

// Schoolbook 4x4 -> 8 limb multiply
void mulWide(uint64_t r[8], const fe a, const fe b) {
    uint64_t t[8] = {0,0,0,0,0,0,0,0};
    for (int i = 0; i < 4; i++) {
        __uint128_t carry = 0;
        for (int j = 0; j < 4; j++) {
            __uint128_t cur = (__uint128_t)a[i] * b[j] + t[i+j] + carry;
            t[i+j] = (uint64_t)cur;
            carry = cur >> 64;
        }
        // propagate remaining carry (result < 2^512 so this terminates)
        size_t k = (size_t)i + 4;
        while (carry) {
            __uint128_t s = (__uint128_t)t[k] + carry;
            t[k] = (uint64_t)s;
            carry = s >> 64;
            k++;
        }
    }
    memcpy(r, t, sizeof(t));
}

// Reduce 510-bit product mod p = 2^255-19 → 4 limbs < 2p (then cond-sub).
// Identity:  x = lo255 + hi * 2^255 ≡ lo255 + hi * 19 (mod p)
void reduceWide(uint64_t out[4], const uint64_t in[8]) {
    // First reduction: split at bit 255
    uint64_t lo[4] = { in[0], in[1], in[2], in[3] & 0x7fffffffffffffffULL };
    uint64_t hi[4] = {
        (in[3] >> 63) | (in[4] << 1),
        (in[4] >> 63) | (in[5] << 1),
        (in[5] >> 63) | (in[6] << 1),
        (in[6] >> 63) | (in[7] << 1)
    };
    // x = lo + hi*19  (< 2^255 + 19*(2^255-1) < 2^259.25)
    uint64_t x[5];
    __uint128_t carry = 0;
    for (int i = 0; i < 4; i++) {
        __uint128_t s = (__uint128_t)lo[i] + (__uint128_t)hi[i] * 19 + carry;
        x[i] = (uint64_t)s;
        carry = s >> 64;
    }
    x[4] = (uint64_t)carry;   // ≤ 18

    // Second reduction: x = lo2 + hi2*19, hi2 = (x3>>63)|(x4<<1) < 2^10
    uint64_t lo2[4] = { x[0], x[1], x[2], x[3] & 0x7fffffffffffffffULL };
    uint64_t hi2v   = (x[3] >> 63) | (x[4] << 1);
    carry = 0;
    for (int i = 0; i < 4; i++) {
        __uint128_t s = (__uint128_t)lo2[i] + (i == 0 ? (__uint128_t)hi2v * 19 : 0) + carry;
        out[i] = (uint64_t)s;
        carry = s >> 64;
    }
    // out < 2^255 + 19*2^10 + 1 → possible carry beyond bit255 folded back:
    // carry means bit 255.. set → add 19 * carry (carry ≤ 1)
    if (carry) {
        __uint128_t c2 = (__uint128_t)out[0] + 19;
        out[0] = (uint64_t)c2;
        c2 >>= 64;
        for (int i = 1; i < 4 && c2; i++) {
            c2 += out[i];
            out[i] = (uint64_t)c2;
            c2 >>= 64;
        }
    }
}

const uint64_t P_MINUS_1[4] = {
    0xffffffffffffffedULL, 0xffffffffffffffffULL,
    0xffffffffffffffffULL, 0x7fffffffffffffffULL
};

// out = a mod p (conditional single subtract — callers guarantee a < 2p)
void condSubP(uint64_t a[4]) {
    uint64_t d[4];
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        __uint128_t sub = (__uint128_t)P_MINUS_1[i] + borrow;
        uint64_t sub_lo = (uint64_t)sub;
        uint64_t sub_hi = (uint64_t)(sub >> 64);   // 1 only when limb is all-ones + borrow
        d[i] = a[i] - sub_lo;
        borrow = ((a[i] < sub_lo) ? 1u : 0u) | sub_hi;
    }
    if (!borrow) {
        memcpy(a, d, sizeof(d));
    }
}

void feAddP(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    __uint128_t carry = 0;
    uint64_t s[4];
    for (int i = 0; i < 4; i++) {
        __uint128_t v = (__uint128_t)a[i] + b[i] + carry;
        s[i] = (uint64_t)v;
        carry = v >> 64;
    }
    // carry (bit 256) can occur only if a,b ≥ 2^255-ish; for inputs < p,
    // s < 2^256 and bit255 may be set → fold it: bit255 = s[3]>>63
    uint64_t bit255 = s[3] >> 63;
    s[3] &= 0x7fffffffffffffffULL;
    if (bit255) {
        __uint128_t v = (__uint128_t)s[0] + 19;
        s[0] = (uint64_t)v;
        uint64_t c = (uint64_t)(v >> 64);
        for (int i = 1; i < 4 && c; i++) {
            v = (__uint128_t)s[i] + c;
            s[i] = (uint64_t)v;
            c = (uint64_t)(v >> 64);
        }
    }
    memcpy(r, s, sizeof(s));
    condSubP(r);
}

void feSubP(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    // r = a - b; if borrow → add p back (mod-p two's complement)
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        __uint128_t sub = (__uint128_t)b[i] + borrow;
        uint64_t sub_lo = (uint64_t)sub;
        uint64_t sub_hi = (uint64_t)(sub >> 64);   // b limb all-ones + borrow
        r[i] = a[i] - sub_lo;
        borrow = ((a[i] < sub_lo) ? 1u : 0u) | sub_hi;
    }
    if (borrow) {
        __uint128_t carry = 0;
        for (int i = 0; i < 4; i++) {
            __uint128_t v = (__uint128_t)r[i] + P_MINUS_1[i] + carry;
            r[i] = (uint64_t)v;
            carry = v >> 64;
        }
    }
}

void feMul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t w[8];
    mulWide(w, a, b);
    reduceWide(r, w);
    condSubP(r);
}

void feSq(uint64_t r[4], const uint64_t a[4]) {
    feMul(r, a, a);
}

// z^(p-2) = z^(2^255-21) — square-and-multiply, MSB→LSB.
// p-2 stored LITTLE-ENDIAN (byte[0] = LSB) to match the bit indexing
// (arr[bit/8] >> bit%8): 0x7f ff … ff eb → eb ff … ff 7f
const uint8_t P_MINUS_2_LE[32] = {
    0xeb,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};

void feInvert(uint64_t r[4], const uint64_t z[4]) {
    uint64_t acc[4] = {1, 0, 0, 0};       // accumulator = z^0
    // iterate bits 254 → 0 of p-2 (bit 255 of p-2 is 0)
    for (int bit = 254; bit >= 0; bit--) {
        feSq(acc, acc);
        if ((P_MINUS_2_LE[bit / 8] >> (bit % 8)) & 1) {
            uint64_t tmp[4];
            feMul(tmp, acc, z);
            memcpy(acc, tmp, sizeof(tmp));
        }
    }
    memcpy(r, acc, sizeof(acc));
}

// Branchless conditional swap
void cswap(uint64_t a[4], uint64_t b[4], uint64_t swap) {
    uint64_t mask = (uint64_t)0 - (swap & 1);
    for (int i = 0; i < 4; i++) {
        uint64_t x = mask & (a[i] ^ b[i]);
        a[i] ^= x;
        b[i] ^= x;
    }
}

// 32-byte secure-ish random from the OS CSPRNG. Returns false on failure.
bool osRandom(uint8_t* out, size_t len) {
#ifdef _WIN32
    // BCryptGenRandom — the OS CSPRNG (no extra deps beyond bcrypt).
    return BCryptGenRandom(NULL, out, (ULONG)len,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return false;
    size_t got = fread(out, 1, len, f);
    fclose(f);
    return got == len;
#endif
}

} // anonymous namespace

void x25519(uint8_t out32[32], const uint8_t scalar32[32], const uint8_t u32[32]) {
    // 1. Clamp the scalar (RFC 7748 §5)
    uint8_t k[32];
    memcpy(k, scalar32, 32);
    k[0]  &= 248;
    k[31] &= 127;
    k[31] |= 64;

    // 2. Decode u (MSB masked); canonicalize (input may be non-canonical
    // per RFC 7748 §5 — must be processed as if reduced mod p)
    uint64_t x1[4];
    feFromBytes(x1, u32);
    condSubP(x1);

    // 3. Montgomery ladder per RFC 7748 §5
    uint64_t x2[4] = {1, 0, 0, 0}, z2[4] = {0, 0, 0, 0};
    uint64_t x3[4],              z3[4] = {1, 0, 0, 0};
    memcpy(x3, x1, sizeof(x1));
    uint64_t swap = 0;

    for (int t = 254; t >= 0; t--) {
        uint64_t kt = (k[t / 8] >> (t % 8)) & 1;
        swap ^= kt;
        cswap(x2, x3, swap);
        cswap(z2, z3, swap);
        swap = kt;

        uint64_t A[4], AA[4], B[4], BB[4], E[4], C[4], D[4], DA[4], CB[4];
        feAddP(A,  x2, z2);
        feSq(AA, A);
        feSubP(B,  x2, z2);
        feSq(BB, B);
        feSubP(E,  AA, BB);
        feAddP(C,  x3, z3);
        feSubP(D,  x3, z3);
        feMul(DA, D, A);
        feMul(CB, C, B);
        uint64_t t1[4], t2[4];
        feAddP(t1, DA, CB);  feSq(t1, t1);   // x3' = (DA+CB)^2
        feSubP(t2, DA, CB);  feSq(t2, t2);   // (DA-CB)^2
        feMul(t2, x1, t2);                    // z3' = x1 * (DA-CB)^2
        memcpy(x3, t1, sizeof(t1));
        memcpy(z3, t2, sizeof(t2));
        feMul(x2, AA, BB);                    // x2' = AA*BB
        uint64_t a24E[4];
        // a24 * E with a24 = 121665: E*121665 = E*(2^17 - 1) ... do two muls
        uint64_t k121665[4] = {121665, 0, 0, 0};
        feMul(a24E, k121665, E);
        feAddP(a24E, AA, a24E);              // AA + a24*E
        feMul(z2, E, a24E);                  // z2' = E * (AA + a24*E)
    }
    cswap(x2, x3, swap);
    cswap(z2, z3, swap);

    // 4. Return x2 * z2^(p-2)
    uint64_t zi[4];
    feInvert(zi, z2);
    uint64_t res[4];
    feMul(res, x2, zi);
    feToBytes(out32, res);

    // best-effort wipe of ladder state
    memset(x2, 0, sizeof(x2)); memset(z2, 0, sizeof(z2));
    memset(x3, 0, sizeof(x3)); memset(z3, 0, sizeof(z3));
    memset(k, 0, sizeof(k));
}

int x25519Keypair(uint8_t priv32[32], uint8_t pub32[32]) {
    if (!osRandom(priv32, 32)) return -1;
    static const uint8_t basepoint[32] = {9};
    x25519(pub32, priv32, basepoint);
    return 0;
}

// ============================================================================
// Handshake helpers
// ============================================================================
namespace {

// transcript = "RSW-HS1" || srv_pub(32) || bot_pub(32) || u16be(id_len) || id
std::vector<uint8_t> buildTranscript(const char* domain,
                                      const uint8_t srv_pub[32],
                                      const uint8_t bot_pub[32],
                                      const std::string& bot_id) {
    std::vector<uint8_t> t;
    size_t dlen = strlen(domain);
    t.insert(t.end(), domain, domain + dlen);
    t.insert(t.end(), srv_pub, srv_pub + 32);
    t.insert(t.end(), bot_pub, bot_pub + 32);
    uint16_t id_len = (uint16_t)bot_id.size();
    t.push_back((uint8_t)(id_len >> 8));
    t.push_back((uint8_t)(id_len & 0xFF));
    t.insert(t.end(), bot_id.begin(), bot_id.end());
    return t;
}

} // anonymous namespace

void deriveSessionKey(const uint8_t shared[32],
                      const uint8_t srv_pub[32],
                      const uint8_t bot_pub[32],
                      const std::string& bot_id,
                      uint8_t session_key_out[32]) {
    auto salt = buildTranscript("RSW-HS1", srv_pub, bot_pub, bot_id);
    static const char info[] = "RSW session key v2";
    hkdfSha256(shared, 32, salt.data(), salt.size(),
               (const uint8_t*)info, sizeof(info) - 1,
               session_key_out, 32);
}

void computeAuthMac(const std::string& psk,
                    const uint8_t srv_pub[32],
                    const uint8_t bot_pub[32],
                    const std::string& bot_id,
                    uint8_t mac_out32[32]) {
    auto t = buildTranscript("RSW-HS1", srv_pub, bot_pub, bot_id);
    hmacSha256((const uint8_t*)psk.data(), psk.size(),
               t.data(), t.size(), mac_out32);
}

void computeConfirmMac(const std::string& psk,
                       const uint8_t srv_pub[32],
                       const uint8_t bot_pub[32],
                       uint8_t mac_out32[32]) {
    std::vector<uint8_t> t;
    static const char dom[] = "RSW-HS2";
    t.insert(t.end(), dom, dom + 7);
    t.insert(t.end(), srv_pub, srv_pub + 32);
    t.insert(t.end(), bot_pub, bot_pub + 32);
    hmacSha256((const uint8_t*)psk.data(), psk.size(),
               t.data(), t.size(), mac_out32);
}

bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

std::string loadPsk() {
    // 1. Environment override (ops can rotate without touching files)
    const char* env_psk = getenv("RSW_PSK");
    if (env_psk && *env_psk) return std::string(env_psk);

    // 2. psk.txt next to the binary / cwd (config file, never hardcoded)
    std::ifstream f("psk.txt");
    if (f) {
        std::string psk;
        if (std::getline(f, psk)) {
            // trim whitespace
            while (!psk.empty() && (psk.back() == '\r' || psk.back() == '\n' ||
                                    psk.back() == ' ' || psk.back() == '\t'))
                psk.pop_back();
            if (!psk.empty()) return psk;
        }
    }

    // 3. No PSK configured → handshake proceeds without mutual auth MAC.
    return std::string();
}
