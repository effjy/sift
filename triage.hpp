// sift — forensic file-triage core engine (header-only, dependency-free)
//
// One translation unit's worth of analysis, shared verbatim by the CLI
// (sift.cpp) and the GTK4 GUI (sift-gui.cpp). Everything here is plain
// C++17 with no third-party dependencies.
//
// What it answers about a single file, fast:
//   * byte-entropy structure   - whole-file + block-by-block Shannon entropy
//   * what it really is         - magic-byte file-type identification
//   * is it lying              - extension vs. real content (masquerade)
//   * is something hidden       - data appended past the format's logical end
//
// These are the first moves of forensic / malware triage, and none of the
// author's other tools (memscan, fordump, frecover, mole) cover them.

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <algorithm>
#include <sys/stat.h>

namespace sift {

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

inline std::string lower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return s;
}

inline uint64_t file_size(const std::string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return 0;
    return (uint64_t)st.st_size;
}

// Read up to `cap` bytes (0 = unlimited). Sets `trunc` if the file is larger
// than what we read, so callers know the analysis is of a prefix only.
inline bool read_file(const std::string& path, std::vector<uint8_t>& out,
                      size_t cap, bool& trunc) {
    trunc = false;
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    out.clear();
    const size_t CH = 1u << 20;        // 1 MiB chunks
    std::vector<uint8_t> buf(CH);
    size_t total = 0;
    for (;;) {
        size_t want = CH;
        if (cap && total + want > cap) want = cap - total;
        if (want == 0) {               // hit the cap: is there more on disk?
            if (std::fgetc(f) != EOF) trunc = true;
            break;
        }
        size_t n = std::fread(buf.data(), 1, want, f);
        if (n == 0) break;
        out.insert(out.end(), buf.begin(), buf.begin() + n);
        total += n;
        if (n < want) break;           // short read => EOF
    }
    std::fclose(f);
    return true;
}

// ---------------------------------------------------------------------------
// Shannon entropy (bits per byte, 0.0 .. 8.0)
// ---------------------------------------------------------------------------

inline double shannon_entropy(const uint8_t* d, size_t n) {
    if (!n) return 0.0;
    size_t freq[256] = {0};
    for (size_t i = 0; i < n; ++i) freq[d[i]]++;
    double bits = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / (double)n;
        bits -= p * std::log2(p);
    }
    return bits;
}

// Split the buffer into `nblocks` equal windows and return one entropy value
// per window. Drives the heatmap in both front-ends.
inline std::vector<double> block_entropy(const uint8_t* d, size_t n, size_t nblocks) {
    std::vector<double> v;
    if (!n || !nblocks) return v;
    size_t bs = (n + nblocks - 1) / nblocks;   // ceil
    if (bs == 0) bs = 1;
    for (size_t off = 0; off < n; off += bs) {
        size_t len = std::min(bs, n - off);
        v.push_back(shannon_entropy(d + off, len));
    }
    return v;
}

inline const char* entropy_label(double e) {
    if (e < 1.0) return "near-constant (padding / zeros)";
    if (e < 5.0) return "structured (text / records)";
    if (e < 7.0) return "mixed (code / markup / binary)";
    if (e < 7.5) return "dense binary";
    if (e < 7.9) return "compressed";
    return "near-random (encrypted or compressed)";
}

// ---------------------------------------------------------------------------
// Magic-byte file-type identification
// ---------------------------------------------------------------------------

struct Sig {
    std::string name;                 // human-readable type
    std::string exts;                 // canonical extensions, comma-separated
    size_t      off1;
    std::vector<uint8_t> m1;
    size_t      off2;                 // optional second anchor (empty m2 = skip)
    std::vector<uint8_t> m2;
};

inline const std::vector<Sig>& signatures() {
    static const std::vector<Sig> T = {
        // executables / objects
        {"ELF binary",            "elf,so,o,bin,out", 0,{0x7F,'E','L','F'}, 0,{}},
        {"PE / DOS executable",   "exe,dll,sys,scr",  0,{'M','Z'},          0,{}},
        {"Mach-O (BE 32)",        "macho,dylib,bin",  0,{0xFE,0xED,0xFA,0xCE},0,{}},
        {"Mach-O (LE 64)",        "macho,dylib,bin",  0,{0xCF,0xFA,0xED,0xFE},0,{}},
        {"Java class / Mach-O FAT","class",           0,{0xCA,0xFE,0xBA,0xBE},0,{}},
        // images
        {"PNG image",             "png",              0,{0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A},0,{}},
        {"JPEG image",            "jpg,jpeg,jpe",     0,{0xFF,0xD8,0xFF},   0,{}},
        {"GIF image",             "gif",              0,{'G','I','F','8'},  0,{}},
        {"BMP image",             "bmp,dib",          0,{'B','M'},          0,{}},
        {"TIFF image (LE)",       "tif,tiff",         0,{'I','I',0x2A,0x00},0,{}},
        {"TIFF image (BE)",       "tif,tiff",         0,{'M','M',0x00,0x2A},0,{}},
        {"ICO icon",              "ico",              0,{0x00,0x00,0x01,0x00},0,{}},
        {"WebP image",            "webp",             0,{'R','I','F','F'},  8,{'W','E','B','P'}},
        // audio / video
        {"WAV audio",             "wav",              0,{'R','I','F','F'},  8,{'W','A','V','E'}},
        {"AVI video",             "avi",              0,{'R','I','F','F'},  8,{'A','V','I',' '}},
        {"OGG media",             "ogg,oga,ogv,opus", 0,{'O','g','g','S'},  0,{}},
        {"FLAC audio",            "flac",             0,{'f','L','a','C'},  0,{}},
        {"MP3 audio (ID3)",       "mp3",              0,{'I','D','3'},      0,{}},
        {"ISO-BMFF (MP4/MOV)",    "mp4,m4a,m4v,mov",  4,{'f','t','y','p'},  0,{}},
        {"Matroska / WebM",       "mkv,webm",         0,{0x1A,0x45,0xDF,0xA3},0,{}},
        // documents
        {"PDF document",          "pdf",              0,{'%','P','D','F'},  0,{}},
        {"PostScript",            "ps,eps",           0,{'%','!'},          0,{}},
        {"RTF document",          "rtf",              0,{'{','\\','r','t','f'},0,{}},
        // archives / compression
        {"ZIP archive",           "zip,jar,apk,docx,xlsx,pptx,odt,ods,odp,epub",0,{'P','K',0x03,0x04},0,{}},
        {"ZIP archive (empty)",   "zip,jar,apk,docx,xlsx,pptx,odt,ods,odp,epub",0,{'P','K',0x05,0x06},0,{}},
        {"gzip",                  "gz,tgz",           0,{0x1F,0x8B},        0,{}},
        {"bzip2",                 "bz2,tbz2",         0,{'B','Z','h'},      0,{}},
        {"xz",                    "xz,txz",           0,{0xFD,'7','z','X','Z',0x00},0,{}},
        {"zstandard",             "zst,tzst",         0,{0x28,0xB5,0x2F,0xFD},0,{}},
        {"LZ4 frame",             "lz4",              0,{0x04,0x22,0x4D,0x18},0,{}},
        {"7-Zip archive",         "7z",               0,{'7','z',0xBC,0xAF,0x27,0x1C},0,{}},
        {"RAR archive",           "rar",              0,{'R','a','r','!',0x1A,0x07},0,{}},
        {"tar archive",           "tar",            257,{'u','s','t','a','r'},0,{}},
        // data / misc
        {"SQLite database",       "sqlite,db,sqlite3",0,{'S','Q','L','i','t','e',' ','f','o','r','m','a','t',' ','3',0x00},0,{}},
        {"PEM / certificate",     "pem,crt,cer,key",  0,{'-','-','-','-','-','B','E','G','I','N'},0,{}},
        {"Shell / script (#!)",   "sh,bash,py,pl",    0,{'#','!'},          0,{}},
        {"XML document",          "xml,svg,xhtml",    0,{'<','?','x','m','l'},0,{}},
    };
    return T;
}

struct Detect {
    bool        matched = false;      // true only for a real magic hit
    std::string name = "data / unknown";
    std::string exts;                 // canonical extensions for the type
};

inline bool match_at(const std::vector<uint8_t>& d, size_t off,
                     const std::vector<uint8_t>& m) {
    if (m.empty()) return true;
    if (off + m.size() > d.size()) return false;
    return std::memcmp(d.data() + off, m.data(), m.size()) == 0;
}

inline bool mostly_text(const std::vector<uint8_t>& d) {
    size_t n = std::min<size_t>(d.size(), 4096), ok = 0;
    if (!n) return false;
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = d[i];
        if (c == 0x09 || c == 0x0A || c == 0x0D || (c >= 0x20 && c <= 0x7E)) ok++;
    }
    return (double)ok / (double)n >= 0.95;
}

inline Detect detect_type(const std::vector<uint8_t>& d) {
    for (const Sig& s : signatures()) {
        if (match_at(d, s.off1, s.m1) && match_at(d, s.off2, s.m2))
            return {true, s.name, s.exts};
    }
    if (mostly_text(d)) return {false, "text / plain", ""};
    return {false, "data / unknown", ""};
}

inline bool ext_in_list(const std::string& ext, const std::string& list) {
    if (ext.empty()) return true;     // no extension => nothing to contradict
    size_t i = 0;
    while (i < list.size()) {
        size_t j = list.find(',', i);
        if (j == std::string::npos) j = list.size();
        if (list.compare(i, j - i, ext) == 0) return true;
        i = j + 1;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Overlay detection — bytes past a format's logical end
// ---------------------------------------------------------------------------

inline long long png_end(const std::vector<uint8_t>& d) {
    if (d.size() < 8) return -1;
    size_t p = 8;
    while (p + 8 <= d.size()) {
        uint32_t len = (uint32_t)d[p] << 24 | (uint32_t)d[p+1] << 16 |
                       (uint32_t)d[p+2] << 8 | d[p+3];
        bool iend = d[p+4]=='I' && d[p+5]=='E' && d[p+6]=='N' && d[p+7]=='D';
        size_t next = p + 8 + (size_t)len + 4;     // header + data + CRC
        if (next > d.size()) return -1;            // corrupt / truncated
        p = next;
        if (iend) return (long long)p;
    }
    return -1;
}

inline long long jpeg_end(const std::vector<uint8_t>& d) {
    if (d.size() < 2 || !(d[0]==0xFF && d[1]==0xD8)) return -1;
    for (size_t i = d.size() - 1; i >= 1; --i) {   // last EOI marker
        if (d[i-1]==0xFF && d[i]==0xD9) return (long long)(i + 1);
        if (i == 1) break;
    }
    return -1;
}

inline long long gif_end(const std::vector<uint8_t>& d) {
    if (d.size() < 6) return -1;
    for (size_t i = d.size(); i-- > 0;) {          // last trailer byte 0x3B
        if (d[i] == 0x3B) return (long long)(i + 1);
        if (i == 0) break;
    }
    return -1;
}

inline long long zip_end(const std::vector<uint8_t>& d) {
    if (d.size() < 22) return -1;
    const uint8_t sig[4] = {'P','K',0x05,0x06};    // End Of Central Directory
    size_t back = d.size() > 65557 ? d.size() - 65557 : 0;
    for (size_t i = d.size() - 22; ; --i) {
        if (std::memcmp(d.data() + i, sig, 4) == 0) {
            uint16_t clen = (uint16_t)d[i+20] | (uint16_t)d[i+21] << 8;
            return (long long)i + 22 + clen;
        }
        if (i == back) break;
    }
    return -1;
}

inline long long pdf_end(const std::vector<uint8_t>& d) {
    const char pat[] = "%%EOF";
    const size_t pl = 5;
    if (d.size() < pl) return -1;
    for (size_t i = d.size() - pl; ; --i) {
        if (std::memcmp(d.data() + i, pat, pl) == 0) return (long long)(i + pl);
        if (i == 0) break;
    }
    return -1;
}

// Returns logical end offset for supported containers, or -1 if we can't tell.
inline long long logical_end(const Detect& t, const std::vector<uint8_t>& d) {
    if (t.name.rfind("PNG", 0) == 0)  return png_end(d);
    if (t.name.rfind("JPEG", 0) == 0) return jpeg_end(d);
    if (t.name.rfind("GIF", 0) == 0)  return gif_end(d);
    if (t.name.rfind("ZIP", 0) == 0)  return zip_end(d);
    if (t.name.rfind("PDF", 0) == 0)  return pdf_end(d);
    return -1;
}

// ---------------------------------------------------------------------------
// Full per-file report
// ---------------------------------------------------------------------------

struct Report {
    std::string         path;
    std::string         name;          // basename
    std::string         ext;           // lowercase, no dot
    uint64_t            size = 0;
    bool                readable = true;
    bool                truncated = false;   // analyzed a prefix only
    double              entropy = 0.0;
    std::vector<double> blocks;
    Detect              type;
    bool                masquerade = false;
    long long           overlay = -1;        // -1 unknown, >=0 trailing bytes
    int                 score = 0;
    std::string         flags;               // e.g. "M O H"
    std::string         verdict;             // clean / review / SUSPICIOUS
};

inline bool type_expects_high_entropy(const std::string& n) {
    static const char* k[] = {"gzip","bzip2","xz","zstd","zstandard","LZ4",
        "7-Zip","RAR","ZIP","JPEG","PNG","GIF","ISO-BMFF","Matroska","OGG",
        "FLAC","MP3","WebP", nullptr};
    for (int i = 0; k[i]; ++i) if (n.find(k[i]) != std::string::npos) return true;
    return false;
}

inline Report analyze(const std::string& path, size_t cap, size_t nblocks) {
    Report r;
    r.path = path;
    size_t slash = path.find_last_of('/');
    r.name = (slash == std::string::npos) ? path : path.substr(slash + 1);
    size_t dot = r.name.find_last_of('.');
    if (dot != std::string::npos && dot + 1 < r.name.size())
        r.ext = lower(r.name.substr(dot + 1));

    std::vector<uint8_t> d;
    if (!read_file(path, d, cap, r.truncated)) { r.readable = false; return r; }
    r.size    = file_size(path);
    r.entropy = shannon_entropy(d.data(), d.size());
    r.blocks  = block_entropy(d.data(), d.size(), nblocks);
    r.type    = detect_type(d);

    if (r.type.matched && !r.type.exts.empty() && !r.ext.empty())
        r.masquerade = !ext_in_list(r.ext, r.type.exts);

    if (!r.truncated) {
        long long end = logical_end(r.type, d);
        if (end >= 0 && end <= (long long)d.size()) {
            long long ov = (long long)d.size() - end;
            if (r.type.name.rfind("PDF", 0) == 0 && ov <= 2) ov = 0;  // trailing newline
            r.overlay = ov;
        }
    }

    // ---- flags, score, verdict ----
    bool highE  = r.entropy >= 7.5;
    bool expect = type_expects_high_entropy(r.type.name);
    std::string fl;
    if (r.masquerade)   fl += fl.empty() ? "M" : " M";
    if (r.overlay > 0)  fl += fl.empty() ? "O" : " O";
    if (highE)          fl += fl.empty() ? "H" : " H";
    r.flags = fl;

    int sc = 0;
    if (r.masquerade) sc += 3;
    if (r.overlay > 0) sc += 2;
    if (highE && !expect && !r.type.matched) sc += 2;   // unexplained random blob
    if (r.masquerade && (r.type.name.rfind("ELF",0)==0 ||
                         r.type.name.rfind("PE ",0)==0 ||
                         r.type.name.rfind("Mach-O",0)==0)) sc += 2;  // hidden executable
    r.score = sc;

    if (!r.readable)      r.verdict = "unreadable";
    else if (sc >= 5)     r.verdict = "SUSPICIOUS";
    else if (sc >= 2)     r.verdict = "review";
    else                  r.verdict = "clean";
    return r;
}

} // namespace sift
