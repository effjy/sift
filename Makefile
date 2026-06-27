# sift v1.0.1 — forensic file triage
#
#   make            build ./sift (CLI) and ./sift-gui (GTK4 GUI)
#   make cli        build only the CLI (no GTK dependency needed)
#   sudo make install     install both + icon/desktop entry
#   sudo make uninstall   remove everything
#   make clean      remove build artifacts
#
# Override on the command line, e.g.:
#   make CXX=clang++ CXXFLAGS='-O3'
#   sudo make install PREFIX=/usr/local

# ---- toolchain ----
CXX      ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra
GUIPKGS   = gtkmm-4.0
GUICFLAGS = $(shell pkg-config --cflags $(GUIPKGS))
GUILIBS   = $(shell pkg-config --libs $(GUIPKGS))

# ---- install layout (GNU-standard, DESTDIR-aware) ----
PREFIX  ?= /usr
BINDIR   = $(PREFIX)/bin
DATADIR  = $(PREFIX)/share
APPDIR   = $(DATADIR)/applications
SVGDIR   = $(DATADIR)/icons/hicolor/scalable/apps
PNGDIR   = $(DATADIR)/icons/hicolor/256x256/apps
DESTDIR ?=

CLI      = sift
GUI      = sift-gui
DESKTOP  = sift.desktop
SVG      = sift.svg
PNG      = sift.png

.PHONY: all cli gui run install uninstall clean help

all: $(CLI) $(GUI)

cli: $(CLI)
gui: $(GUI)

$(CLI): sift.cpp triage.hpp
	$(CXX) $(CXXFLAGS) -o $@ sift.cpp

$(GUI): sift-gui.cpp triage.hpp
	$(CXX) $(CXXFLAGS) $(GUICFLAGS) -o $@ sift-gui.cpp $(GUILIBS)

run: $(CLI)
	./$(CLI) --help

install: all
	install -Dm755 $(CLI)     $(DESTDIR)$(BINDIR)/$(CLI)
	install -Dm755 $(GUI)     $(DESTDIR)$(BINDIR)/$(GUI)
	install -Dm644 $(DESKTOP) $(DESTDIR)$(APPDIR)/$(DESKTOP)
	install -Dm644 $(SVG)     $(DESTDIR)$(SVGDIR)/$(SVG)
	install -Dm644 $(PNG)     $(DESTDIR)$(PNGDIR)/$(PNG)
	-gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	@echo "Installed sift + sift-gui to $(DESTDIR)$(BINDIR)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(CLI)
	rm -f $(DESTDIR)$(BINDIR)/$(GUI)
	rm -f $(DESTDIR)$(APPDIR)/$(DESKTOP)
	rm -f $(DESTDIR)$(SVGDIR)/$(SVG)
	rm -f $(DESTDIR)$(PNGDIR)/$(PNG)
	-gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	@echo "Uninstalled sift"

clean:
	rm -f $(CLI) $(GUI)

help:
	@echo "Targets: all cli gui run install uninstall clean"
	@echo "Vars:    CXX CXXFLAGS PREFIX(=$(PREFIX)) DESTDIR"
