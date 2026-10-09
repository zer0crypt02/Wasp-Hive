// ============================================================================
// keyexchange.h — X25519 ECDH + SHA-256/HMAC/HKDF key derivation
// ============================================================================
// Replaces the fixed-XOR session key delivery with a real ephemeral key
// exchange (forward secrecy) and adds mutual authentication (HMAC over the
// transcript with a pre-shared key from config/env — never hardcoded).
//
// Standards:
//   - X25519: RFC 7748 (Curve25519 scalar multiplication)
//   - SHA-256: FIPS 180-4
//   - HMAC-SHA256: RFC 2104
//   - HKDF: RFC 5869
//
// Pure C++ — zero external dependencies (matches crypto.h philosophy).
// Verified against RFC 7748 §5.2 test vectors (see tests/test_kex.cpp).
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

// ---- SHA-256 (FIPS 180-4) ----
// out32 must point to 32 bytes. data may be empty.
void sha256(const uint8_t* data, size_t len, uint8_t out32[32]);

// ---- HMAC-SHA256 (RFC 2104) ----
void hmacSha256(const uint8_t* key, size_t key_len,
                const uint8_t* msg, size_t msg_len,
                uint8_t out32[32]);

// ---- HKDF-SHA256 (RFC 5869) ----
// extract: PRK = HMAC(salt, ikm); expand: OKM (out_len bytes, <= 255*32).
// salt may be null (defaults to HashLen zero bytes per RFC), same for info.
void hkdfSha256(const uint8_t* ikm, size_t ikm_len,
                const uint8_t* salt, size_t salt_len,
                const uint8_t* info, size_t info_len,
                uint8_t* out, size_t out_len);

// ---- X25519 (RFC 7748) ----
// out32 = X25519(scalar32, u32). Clamping and MSB masking per RFC 7748.
// Constant-time Montgomery ladder; NOT side-channel hardened against
// power/EM analysis but timing-attack safe (branchless cswap).
void x25519(uint8_t out32[32], const uint8_t scalar32[32], const uint8_t u32[32]);

// Generate an ephemeral X25519 keypair (private = random 32B, clamped at use).
// Returns 0 on success, -1 if the system RNG fails.
int x25519Keypair(uint8_t priv32[32], uint8_t pub32[32]);

// ============================================================================
// Handshake helpers (used by RSW.cpp server + c2_agent.cpp bot)
// ============================================================================

// server_pub = X25519(server_priv, base9) — done by x25519Keypair on server.
//
// shared_secret = X25519(my_priv, peer_pub)
// session_key   = HKDF-SHA256(ikm = shared, salt = transcript, info = label)
//
// transcript   = "RSW-HS1" || srv_pub(32) || bot_pub(32) || bot_id
// auth_mac     = HMAC-SHA256(psk, transcript)   — sent by server (proves PSK)
// confirm_mac  = HMAC-SHA256(psk, "RSW-HS2" || srv_pub || bot_pub)
//                                              — sent by bot (proves PSK)
//
// All byte fields in transcript are length-prefixed where variable
// (bot_id): u16be(len) || bytes — prevents length-extension ambiguity.

// Derive the 32-byte session key from an ECDH shared secret + transcript.
void deriveSessionKey(const uint8_t shared[32],
                      const uint8_t srv_pub[32],
                      const uint8_t bot_pub[32],
                      const std::string& bot_id,
                      uint8_t session_key_out[32]);

// Compute the server→bot auth MAC (over transcript) with the given PSK.
void computeAuthMac(const std::string& psk,
                    const uint8_t srv_pub[32],
                    const uint8_t bot_pub[32],
                    const std::string& bot_id,
                    uint8_t mac_out32[32]);

// Compute the bot→server confirm MAC (RSW-HS2 domain).
void computeConfirmMac(const std::string& psk,
                       const uint8_t srv_pub[32],
                       const uint8_t bot_pub[32],
                       uint8_t mac_out32[32]);

// Constant-time compare (prevents timing attacks on MAC checks).
bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len);

// Load the pre-shared key for mutual auth.
// Priority: RSW_PSK env var → psk.txt file → "" (auth disabled).
// NEVER a hardcoded default (CLAUDE.md: no embedded credentials) —
// without a PSK the handshake still completes (ECDH + session key),
// just without the mutual-auth MAC layer.
std::string loadPsk();
