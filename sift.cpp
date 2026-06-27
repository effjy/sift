// sift v1.0.1 — forensic file triage (CLI)  ·  binary: sift
//
// Profiles a file's byte-entropy structure, identifies what it really is from
// its magic bytes, flags extension/content mismatches (masquerade), and finds
// data appended past a format's logical end (a classic exfil / stego trick).
//
//   sift <file>                 full report + entropy heatmap
//   sift -r <dir> [dir...]      recursive triage table, ranked by suspicion
//   sift <file> <file> ...      report each
//
// Dependency-free C++17. See triage.hpp for the analysis engine.

#include "triage.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <filesystem>
#include <unistd.h>
#include <sys/ioctl.h>

namespace fs = std::filesystem;
using sift::Report;

namespace {

const size_t CAP_SINGLE = (size_t)512 << 20;   // 512 MiB for a single target
const size_t CAP_RECURSE = (size_t)16 << 20;   //  16 MiB per file when walking

bool g_color = true;

int term_width() {
    struct winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return ws.ws_col;
    return 80;
}

// entropy 0..8 -> RGB rainbow (blue=low, red=high) via HSV(240..0)
void heat_rgb(double e, int& R, int& G, int& B) {
    double t = e / 8.0; if (t < 0) t = 0; if (t > 1) t = 1;
    double h = (1.0 - t) * 240.0 / 60.0;        // sector 0..4
    int i = (int)h; double f = h - i;
    double v = 1.0, p = 0.0, q = 1.0 - f, u = f;
    double r, g, b;
    switch (i) {
        case 0: r=v; g=u; b=p; break;
        case 1: r=q; g=v; b=p; break;
        case 2: r=p; g=v; b=u; break;
        case 3: r=p; g=q; b=v; break;
        default:r=u; g=p; b=v; break;
    }
    R = (int)(r*255); G = (int)(g*255); B = (int)(b*255);
}

std::string human(uint64_t n) {
    const char* u[] = {"B","KiB","MiB","GiB","TiB"};
    double v = (double)n; int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; ++i; }
    char buf[32];
    std::snprintf(buf, sizeof buf, i ? "%.1f %s" : "%.0f %s", v, u[i]);
    return buf;
}

void print_heatmap(const Report& r, int width) {
    if (r.blocks.empty()) return;
    // Offset ruler.
    std::string left = "0";
    std::string right = "0x" + [&]{ char b[24]; std::snprintf(b,sizeof b,"%llx",(unsigned long long)r.size); return std::string(b); }();
    std::printf("  %s", left.c_str());
    int pad = width - (int)left.size() - (int)right.size();
    for (int i = 0; i < pad; ++i) std::putchar(' ');
    std::printf("%s\n", right.c_str());

    // The strip itself.
    std::fputs("  ", stdout);
    const char* ramp = " .:-=+*#%@";
    for (int c = 0; c < width; ++c) {
        size_t idx = (size_t)((double)c / width * r.blocks.size());
        if (idx >= r.blocks.size()) idx = r.blocks.size() - 1;
        double e = r.blocks[idx];
        if (g_color) {
            int R,G,B; heat_rgb(e,R,G,B);
            std::printf("\x1b[48;2;%d;%d;%dm \x1b[0m", R, G, B);
        } else {
            int k = (int)(e / 8.0 * 9.0); if (k < 0) k = 0; if (k > 9) k = 9;
            std::putchar(ramp[k]);
        }
    }
    std::putchar('\n');

    // Legend.
    std::fputs("  low ", stdout);
    if (g_color) {
        for (double e = 0; e <= 8.0; e += 8.0/16) {
            int R,G,B; heat_rgb(e,R,G,B);
            std::printf("\x1b[48;2;%d;%d;%dm \x1b[0m", R, G, B);
        }
    } else std::fputs(" ........@@@@ ", stdout);
    std::fputs(" high entropy (0 \xe2\x86\x92 8 bits/byte)\n", stdout);
}

void report_one(const std::string& path, int width) {
    Report r = sift::analyze(path, CAP_SINGLE, width > 8 ? (size_t)width : 64);
    std::printf("\n\x1b[1m%s\x1b[0m\n", r.path.c_str());
    if (!r.readable) { std::printf("  cannot read file\n"); return; }

    std::printf("  size        %s (%llu bytes)%s\n", human(r.size).c_str(),
                (unsigned long long)r.size, r.truncated ? "  [analyzed prefix]" : "");
    std::printf("  type        %s%s\n", r.type.name.c_str(),
                r.type.matched ? "" : "  (no magic signature)");
    std::printf("  extension   %s\n", r.ext.empty() ? "(none)" : ("." + r.ext).c_str());
    std::printf("  entropy     %.3f bits/byte  \xe2\x80\x94 %s\n",
                r.entropy, sift::entropy_label(r.entropy));

    if (r.masquerade)
        std::printf("  \x1b[1;31mMASQUERADE\x1b[0m  content is %s but extension is .%s\n",
                    r.type.name.c_str(), r.ext.c_str());
    if (r.overlay > 0)
        std::printf("  \x1b[1;33mOVERLAY\x1b[0m     %s appended past the %s logical end\n",
                    human((uint64_t)r.overlay).c_str(), r.type.name.c_str());

    std::printf("\n");
    print_heatmap(r, width - 4);

    const char* col = r.score >= 5 ? "1;31" : r.score >= 2 ? "1;33" : "1;32";
    std::printf("\n  verdict     \x1b[%sm%s\x1b[0m  (score %d%s%s)\n\n",
                col, r.verdict.c_str(), r.score,
                r.flags.empty() ? "" : ", flags ", r.flags.c_str());
}

void collect(const std::string& root, std::vector<Report>& out) {
    std::error_code ec;
    if (fs::is_directory(root, ec)) {
        auto it = fs::recursive_directory_iterator(
            root, fs::directory_options::skip_permission_denied, ec);
        for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (!it->is_regular_file(ec)) continue;
            out.push_back(sift::analyze(it->path().string(), CAP_RECURSE, 1));
        }
    } else {
        out.push_back(sift::analyze(root, CAP_RECURSE, 1));
    }
}

void recurse_table(const std::vector<std::string>& roots, bool show_all) {
    std::vector<Report> rs;
    for (auto& root : roots) collect(root, rs);
    std::stable_sort(rs.begin(), rs.end(),
        [](const Report& a, const Report& b) {
            if (a.score != b.score) return a.score > b.score;
            return a.entropy > b.entropy;
        });

    std::printf("\n\x1b[1m%-4s %-5s %-7s %-26s %-7s %s\x1b[0m\n",
                "RISK", "FLAGS", "ENTROPY", "TYPE", "EXT", "PATH");
    int shown = 0, susp = 0, masq = 0, ovl = 0;
    for (const Report& r : rs) {
        if (r.masquerade) masq++;
        if (r.overlay > 0) ovl++;
        if (r.score >= 5) susp++;
        if (!show_all && r.score == 0) continue;
        ++shown;
        const char* col = r.score >= 5 ? "1;31" : r.score >= 2 ? "1;33" : "0";
        std::printf("\x1b[%sm%-4d %-5s %7.3f %-26.26s %-7.7s %s\x1b[0m\n",
                    col, r.score, r.flags.empty() ? "-" : r.flags.c_str(),
                    r.entropy, r.type.name.c_str(),
                    r.ext.empty() ? "-" : r.ext.c_str(), r.path.c_str());
    }
    std::printf("\n  %zu files scanned · %d flagged · %d suspicious · "
                "%d masquerade · %d overlay\n",
                rs.size(), shown, susp, masq, ovl);
    std::printf("  flags: M=masquerade  O=overlay/appended  H=high-entropy"
                "%s\n\n", show_all ? "" : "   (use -a to list clean files)");
}

void usage() {
    std::puts(
        "sift v1.0.1 — forensic file triage\n\n"
        "Usage:\n"
        "  sift <file> [file...]      full report + entropy heatmap per file\n"
        "  sift -r <path> [path...]   recursive triage table, ranked by risk\n\n"
        "Options:\n"
        "  -r, --recursive   walk directories and print a ranked table\n"
        "  -a, --all         in table mode, also list clean (score 0) files\n"
        "  -C, --no-color    disable ANSI color\n"
        "  -h, --help        this help\n");
}

} // namespace

int main(int argc, char** argv) {
    if (!isatty(STDOUT_FILENO) || std::getenv("NO_COLOR")) g_color = false;

    bool recursive = false, show_all = false;
    std::vector<std::string> targets;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "-h" || a == "--help")      { usage(); return 0; }
        else if (a == "-r" || a == "--recursive") recursive = true;
        else if (a == "-a" || a == "--all")       show_all = true;
        else if (a == "-C" || a == "--no-color")  g_color = false;
        else if (!a.empty() && a[0] == '-')       { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); return 2; }
        else                                      targets.push_back(a);
    }
    if (targets.empty()) { usage(); return 2; }

    if (recursive) {
        recurse_table(targets, show_all);
    } else {
        int w = term_width(); if (w > 120) w = 120;
        for (auto& t : targets) {
            std::error_code ec;
            if (fs::is_directory(t, ec)) {
                std::fprintf(stderr, "%s is a directory; use -r to scan it\n", t.c_str());
                continue;
            }
            report_one(t, w);
        }
    }
    return 0;
}
