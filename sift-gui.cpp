// sift-gui v1.0.1 — forensic file triage (GTK4 / gtkmm-4.0)
//
// A horizontal triage dashboard: pick a folder (or a file), get a ranked
// table of everything in it, and click any row to see its entropy heatmap
// and verdict. Same analysis engine as the CLI (triage.hpp).
//
// Layout is deliberately wide-and-short to fit a 1366x768 laptop panel.

#include "triage.hpp"

#include <gtkmm.h>
#include <filesystem>
#include <vector>
#include <memory>
#include <algorithm>

namespace fs = std::filesystem;
using sift::Report;

namespace {
const char*  APP_VERSION = "1.0.1";
const char*  APP_URL     = "https://github.com/effjy/sift/";
const size_t CAP   = (size_t)64 << 20;   // 64 MiB analyzed per file
const size_t NBLKS = 320;                // heatmap resolution

void heat_rgb(double e, double& R, double& G, double& B) {
    double t = e / 8.0; if (t < 0) t = 0; if (t > 1) t = 1;
    double h = (1.0 - t) * 240.0 / 60.0;
    int i = (int)h; double f = h - i;
    double v = 1.0, p = 0.0, q = 1.0 - f, u = f;
    switch (i) {
        case 0: R=v; G=u; B=p; break;
        case 1: R=q; G=v; B=p; break;
        case 2: R=p; G=v; B=u; break;
        case 3: R=p; G=q; B=v; break;
        default:R=u; G=p; B=v; break;
    }
}
std::string human(uint64_t n) {
    const char* u[] = {"B","KiB","MiB","GiB","TiB"};
    double v = (double)n; int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; ++i; }
    char b[32]; std::snprintf(b, sizeof b, i ? "%.1f %s" : "%.0f %s", v, u[i]);
    return b;
}
} // namespace

// ---------------------------------------------------------------------------

class SiftWindow : public Gtk::ApplicationWindow {
public:
    SiftWindow();

private:
    // model
    struct Cols : public Gtk::TreeModel::ColumnRecord {
        Gtk::TreeModelColumn<int>         risk;
        Gtk::TreeModelColumn<Glib::ustring> flags, entropy, type, ext, name;
        Gtk::TreeModelColumn<guint>       idx;     // index into m_reports
        Cols() { add(risk); add(flags); add(entropy); add(type); add(ext); add(name); add(idx); }
    };
    Cols m_cols;
    Glib::RefPtr<Gtk::ListStore> m_store;
    Gtk::TreeView m_view;

    std::vector<Report> m_reports;
    const Report*       m_sel = nullptr;

    // right-hand detail widgets
    Gtk::Label   m_d_name, m_d_size, m_d_type, m_d_ext, m_d_entropy, m_d_verdict, m_d_flags;
    Gtk::DrawingArea m_heat;
    Gtk::Label   m_status;

    void build_ui();
    void show_about();
    void choose_folder();
    void choose_file();
    void scan_paths(const std::vector<std::string>& roots);
    void reload_table();
    void on_selection_changed();
    void draw_heat(const Cairo::RefPtr<Cairo::Context>& cr, int w, int h);
    Gtk::Label* detail_row(Gtk::Grid& g, int row, const char* key, Gtk::Label& val);
};

SiftWindow::SiftWindow() { build_ui(); }

Gtk::Label* SiftWindow::detail_row(Gtk::Grid& g, int row, const char* key, Gtk::Label& val) {
    auto* k = Gtk::make_managed<Gtk::Label>(key);
    k->set_xalign(0.f);
    k->add_css_class("dim-label");
    val.set_xalign(0.f);
    val.set_wrap(true);
    val.set_selectable(true);
    g.attach(*k, 0, row);
    g.attach(val, 1, row);
    return k;
}

void SiftWindow::build_ui() {
    set_title("sift — forensic file triage");
    set_icon_name("sift");
    set_default_size(1180, 560);          // wide and short

    // ---- header bar ----
    auto* header = Gtk::make_managed<Gtk::HeaderBar>();
    set_titlebar(*header);
    auto* btn_folder = Gtk::make_managed<Gtk::Button>("Scan Folder…");
    auto* btn_file   = Gtk::make_managed<Gtk::Button>("Scan File…");
    btn_folder->signal_clicked().connect(sigc::mem_fun(*this, &SiftWindow::choose_folder));
    btn_file->signal_clicked().connect(sigc::mem_fun(*this, &SiftWindow::choose_file));
    header->pack_start(*btn_folder);
    header->pack_start(*btn_file);
    auto* btn_about = Gtk::make_managed<Gtk::Button>();
    btn_about->set_icon_name("help-about-symbolic");
    btn_about->set_tooltip_text("About sift");
    btn_about->signal_clicked().connect(sigc::mem_fun(*this, &SiftWindow::show_about));
    header->pack_end(*btn_about);

    // ---- root: horizontal split ----
    auto* root = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::VERTICAL, 0);
    set_child(*root);
    auto* split = Gtk::make_managed<Gtk::Paned>(Gtk::Orientation::HORIZONTAL);
    split->set_vexpand(true);
    root->append(*split);

    // ---- left: results table ----
    m_store = Gtk::ListStore::create(m_cols);
    m_view.set_model(m_store);
    m_view.append_column("Risk",    m_cols.risk);
    m_view.append_column("Flags",   m_cols.flags);
    m_view.append_column("Entropy", m_cols.entropy);
    m_view.append_column("Type",    m_cols.type);
    m_view.append_column("Ext",     m_cols.ext);
    m_view.append_column("Name",    m_cols.name);
    for (auto* c : m_view.get_columns()) { c->set_resizable(true); c->set_sort_indicator(false); }
    m_view.get_selection()->signal_changed().connect(
        sigc::mem_fun(*this, &SiftWindow::on_selection_changed));

    auto* sc = Gtk::make_managed<Gtk::ScrolledWindow>();
    sc->set_policy(Gtk::PolicyType::AUTOMATIC, Gtk::PolicyType::AUTOMATIC);
    sc->set_child(m_view);
    sc->set_size_request(680, -1);
    split->set_start_child(*sc);
    split->set_resize_start_child(true);

    // ---- right: details + heatmap ----
    auto* right = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::VERTICAL, 10);
    right->set_margin(12);
    right->set_size_request(420, -1);

    auto* title = Gtk::make_managed<Gtk::Label>();
    title->set_markup("<b>Details</b>");
    title->set_xalign(0.f);
    right->append(*title);

    auto* grid = Gtk::make_managed<Gtk::Grid>();
    grid->set_row_spacing(6);
    grid->set_column_spacing(14);
    detail_row(*grid, 0, "File",     m_d_name);
    detail_row(*grid, 1, "Size",     m_d_size);
    detail_row(*grid, 2, "Type",     m_d_type);
    detail_row(*grid, 3, "Extension",m_d_ext);
    detail_row(*grid, 4, "Entropy",  m_d_entropy);
    detail_row(*grid, 5, "Flags",    m_d_flags);
    detail_row(*grid, 6, "Verdict",  m_d_verdict);
    right->append(*grid);

    auto* hl = Gtk::make_managed<Gtk::Label>();
    hl->set_markup("<b>Entropy map</b>  <span size='small'>blue 0 → red 8 bits/byte</span>");
    hl->set_xalign(0.f);
    hl->set_margin_top(6);
    right->append(*hl);

    m_heat.set_content_height(96);
    m_heat.set_hexpand(true);
    m_heat.set_draw_func(sigc::mem_fun(*this, &SiftWindow::draw_heat));
    right->append(m_heat);

    split->set_end_child(*right);
    split->set_resize_end_child(false);

    // ---- status bar ----
    m_status.set_xalign(0.f);
    m_status.set_margin_start(10);
    m_status.set_margin_top(4);
    m_status.set_margin_bottom(4);
    m_status.set_markup("<span size='small'>Pick a folder or file to begin.  "
                        "Flags: <b>M</b> masquerade · <b>O</b> overlay/appended · "
                        "<b>H</b> high-entropy.</span>");
    root->append(m_status);
}

void SiftWindow::show_about() {
    auto* about = new Gtk::AboutDialog();
    about->set_transient_for(*this);
    about->set_modal(true);
    about->set_program_name("sift");
    about->set_version(APP_VERSION);
    about->set_logo_icon_name("sift");
    about->set_comments("Forensic file triage — entropy heatmaps, magic-byte "
                        "type identification, and masquerade / overlay detection.");
    about->set_copyright("© 2026 Jean-Francois Lachance-Caumartin");
    about->set_license_type(Gtk::License::MIT_X11);
    about->set_website(APP_URL);
    about->set_website_label(APP_URL);
    about->set_authors({ "Jean-Francois Lachance-Caumartin" });
    about->signal_hide().connect([about]{ delete about; });
    about->present();
}

void SiftWindow::choose_folder() {
    auto dlg = Gtk::FileDialog::create();
    dlg->set_title("Choose a folder to triage");
    dlg->select_folder(*this, [this, dlg](Glib::RefPtr<Gio::AsyncResult>& res) {
        try {
            auto f = dlg->select_folder_finish(res);
            if (f) scan_paths({ f->get_path() });
        } catch (const Glib::Error&) { /* cancelled */ }
    });
}

void SiftWindow::choose_file() {
    auto dlg = Gtk::FileDialog::create();
    dlg->set_title("Choose a file to triage");
    dlg->open(*this, [this, dlg](Glib::RefPtr<Gio::AsyncResult>& res) {
        try {
            auto f = dlg->open_finish(res);
            if (f) scan_paths({ f->get_path() });
        } catch (const Glib::Error&) { /* cancelled */ }
    });
}

void SiftWindow::scan_paths(const std::vector<std::string>& roots) {
    m_reports.clear();
    std::error_code ec;
    for (const auto& root : roots) {
        if (fs::is_directory(root, ec)) {
            auto it = fs::recursive_directory_iterator(
                root, fs::directory_options::skip_permission_denied, ec);
            for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
                if (ec) { ec.clear(); continue; }
                if (!it->is_regular_file(ec)) continue;
                m_reports.push_back(sift::analyze(it->path().string(), CAP, NBLKS));
            }
        } else {
            m_reports.push_back(sift::analyze(root, CAP, NBLKS));
        }
    }
    std::stable_sort(m_reports.begin(), m_reports.end(),
        [](const Report& a, const Report& b) {
            if (a.score != b.score) return a.score > b.score;
            return a.entropy > b.entropy;
        });
    reload_table();
}

void SiftWindow::reload_table() {
    m_store->clear();
    int susp = 0, masq = 0, ovl = 0;
    for (guint i = 0; i < m_reports.size(); ++i) {
        const Report& r = m_reports[i];
        if (r.score >= 5) susp++;
        if (r.masquerade) masq++;
        if (r.overlay > 0) ovl++;
        auto row = *m_store->append();
        row[m_cols.risk]    = r.score;
        row[m_cols.flags]   = r.flags.empty() ? "—" : r.flags;
        char eb[16]; std::snprintf(eb, sizeof eb, "%.3f", r.entropy);
        row[m_cols.entropy] = eb;
        row[m_cols.type]    = r.type.name;
        row[m_cols.ext]     = r.ext.empty() ? "—" : r.ext;
        row[m_cols.name]    = r.name;
        row[m_cols.idx]     = i;
    }
    char buf[256];
    std::snprintf(buf, sizeof buf,
        "<span size='small'>%zu files · <b>%d</b> suspicious · %d masquerade · "
        "%d overlay.  Flags: <b>M</b> masquerade · <b>O</b> overlay · <b>H</b> high-entropy.</span>",
        m_reports.size(), susp, masq, ovl);
    m_status.set_markup(buf);
    if (!m_reports.empty()) {
        m_view.get_selection()->select(m_store->children().begin());
    } else {
        m_sel = nullptr; m_heat.queue_draw();
    }
}

void SiftWindow::on_selection_changed() {
    auto it = m_view.get_selection()->get_selected();
    if (!it) { m_sel = nullptr; m_heat.queue_draw(); return; }
    guint idx = (*it)[m_cols.idx];
    if (idx >= m_reports.size()) return;
    const Report& r = m_reports[idx];
    m_sel = &r;

    m_d_name.set_text(r.path);
    m_d_size.set_text(human(r.size) + (r.truncated ? "  (analyzed prefix)" : ""));
    m_d_type.set_text(r.type.name + (r.type.matched ? "" : "  (no magic)"));
    m_d_ext.set_text(r.ext.empty() ? "(none)" : "." + r.ext);
    char eb[96]; std::snprintf(eb, sizeof eb, "%.3f bits/byte — %s",
                               r.entropy, sift::entropy_label(r.entropy));
    m_d_entropy.set_text(eb);

    std::string fl;
    if (r.masquerade) fl += "MASQUERADE (content ≠ extension)  ";
    if (r.overlay > 0) fl += "OVERLAY (" + human((uint64_t)r.overlay) + " appended)  ";
    if (r.flags.find('H') != std::string::npos) fl += "high-entropy";
    m_d_flags.set_text(fl.empty() ? "none" : fl);

    const char* col = r.score >= 5 ? "#ff5c5c" : r.score >= 2 ? "#e2c044" : "#2ecc71";
    char vb[160];
    std::snprintf(vb, sizeof vb, "<span foreground='%s'><b>%s</b></span>  (score %d)",
                  col, r.verdict.c_str(), r.score);
    m_d_verdict.set_markup(vb);

    m_heat.queue_draw();
}

void SiftWindow::draw_heat(const Cairo::RefPtr<Cairo::Context>& cr, int w, int h) {
    cr->set_source_rgb(0.07, 0.08, 0.10);     // backdrop
    cr->paint();
    if (!m_sel || m_sel->blocks.empty()) return;
    const auto& b = m_sel->blocks;
    for (int x = 0; x < w; ++x) {
        size_t i = (size_t)((double)x / w * b.size());
        if (i >= b.size()) i = b.size() - 1;
        double R, G, B; heat_rgb(b[i], R, G, B);
        cr->set_source_rgb(R, G, B);
        cr->rectangle(x, 0, 1, h);
        cr->fill();
    }
}

// ---------------------------------------------------------------------------

class SiftApp : public Gtk::Application {
protected:
    SiftApp() : Gtk::Application("com.github.effjy.sift") {}
    void on_activate() override {
        auto* w = new SiftWindow();
        add_window(*w);
        w->signal_hide().connect([w]{ delete w; });
        w->present();
    }
public:
    static Glib::RefPtr<SiftApp> create() { return Glib::make_refptr_for_instance(new SiftApp()); }
};

int main(int argc, char** argv) {
    // Pin the X11 WM_CLASS / Wayland app-id base so the window reliably maps to
    // sift.desktop (StartupWMClass=sift-gui) and shows the installed icon in
    // the taskbar when installed globally.
    Glib::set_prgname("sift-gui");
    return SiftApp::create()->run(argc, argv);
}
