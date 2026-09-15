# OPSEC Notes: SentinelOne + Carbon Black App Control

## What will catch you and where

### Carbon Black App Control (formerly Cb Protection)
Carbon Black App Control is an **application whitelisting** product. This is your bigger
problem — it operates at a fundamentally different level than AV/EDR.

**It will block your loader.exe from running at all** unless:
- The binary is on the approved/whitelist
- It's signed by a trusted publisher
- It's in an approved path
- An admin has put the endpoint in a permissive mode

Carbon Black App Control intercepts `CreateProcess` and checks the binary hash against
its trust database before it ever executes. Your cross-compiled MinGW PE will be
unknown and unsigned → **blocked at launch**.

**Bypasses to research:**
- If CB App Control is in "monitor only" / "visibility" mode rather than "block",
  your binary will run but generate alerts
- Living-off-the-land: use a trusted/whitelisted binary as your host process.
  Candidates that are typically whitelisted:
  - `msbuild.exe` — can execute inline C# tasks from an XML file (the XML is not
    subject to app control, only the EXE is)
  - `installutil.exe` — executes code via the `[RunInstaller]` attribute
  - `regsvcs.exe` / `regasm.exe` — .NET COM registration utilities
  - `cmstp.exe` — Connection Manager Profile Installer
  - `rundll32.exe` — if DLLs from approved paths are allowed
- These are all Microsoft-signed .NET Framework utilities that ship with Windows
  and are typically whitelisted. They can load arbitrary .NET code.

### SentinelOne EDR
S1 hooks at multiple levels. Here's what it will see with the current loader:

**Static detection:**
- Import table containing `CLRCreateInstance` or loading `mscoree.dll` is a known
  indicator. The dynamic `LoadLibrary("mscoree.dll")` approach in the loaders
  avoids the import table entry but S1's static engine may still flag patterns.
- XOR-encrypted blobs in .data section are a heuristic trigger (low-entropy key
  XOR'd against high-entropy ciphertext creates recognizable patterns).

**Behavioral detection:**
- **CLR load in unmanaged process**: S1 monitors for `clrjit.dll` and `clr.dll`
  being loaded into processes that aren't normally managed. This is the #1
  behavioral indicator for execute-assembly techniques.
- **AMSI**: On Windows 10+, `Assembly.Load(byte[])` triggers AMSI scanning.
  S1 subscribes to AMSI events. Your decrypted assembly bytes will be scanned.
- **ETW (Event Tracing for Windows)**: The `Microsoft-Windows-DotNETRuntime`
  provider logs assembly loads including the assembly name, even from byte arrays.
  S1 consumes these events.
- **Console output redirection**: If the assembly writes to Console.Out, the
  output routing through pipes can be flagged.

## What you need to add to this toolkit

### 1. AMSI Bypass (critical — do this first)
AMSI will scan whatever you pass to `Assembly.Load()`. You need to patch it
before the CLR load. Common approaches:

**Patch amsi.dll!AmsiScanBuffer in the current process:**
The function is loaded into your process when the CLR initializes. Patch it to
return `AMSI_RESULT_CLEAN` (S_OK) before calling `Assembly.Load()`.

```
// After CLR Start() but before AppDomain.Load():
// 1. GetModuleHandle("amsi.dll")  (loaded by CLR init)
// 2. GetProcAddress → AmsiScanBuffer
// 3. VirtualProtect the first bytes to PAGE_EXECUTE_READWRITE
// 4. Patch with bytes that return S_OK immediately
// 5. VirtualProtect back to original
```

The classic patch bytes for x64 are:
```
mov eax, 0x80070057   ; E_INVALIDARG — tells caller "nothing to scan"
ret
; Bytes: B8 57 00 07 80 C3
```

**Note:** S1 may hook VirtualProtect on amsi.dll's pages, or monitor for
the specific patch pattern. Consider:
- Using hardware breakpoints (DR0-DR3) to redirect execution instead of patching
- Patching AmsiOpenSession instead of AmsiScanBuffer (less monitored)
- Loading a second copy of amsi.dll and patching that

### 2. ETW Bypass
Patch `ntdll!EtwEventWrite` to neuter the .NET runtime telemetry:

```
// Before CLR Start():
// 1. GetModuleHandle("ntdll.dll")
// 2. GetProcAddress → EtwEventWrite
// 3. Patch with: xor eax,eax; ret (return SUCCESS, do nothing)
; Bytes: 33 C0 C3
```

**Warning:** S1 may detect ETW tampering. Alternatives:
- Patch only the .NET runtime's specific ETW registration rather than global ntdll
- Use `NtTraceControl` to disable specific providers
- Unhook only for the duration of your load, then restore

### 3. For Carbon Black App Control — use a LOLBin host

Instead of running your own loader.exe, inject your CLR hosting logic into
a whitelisted process. Best options:

**Option A: MSBuild inline task**
Create a `.csproj` or `.xml` file containing your loader as an inline C# task.
MSBuild.exe is Microsoft-signed and almost always whitelisted.

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Run">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory"
             AssemblyFile="C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <!-- Your Assembly.Load(byte[]) code goes here as a managed class -->
      </Code>
    </Task>
  </UsingTask>
</Project>
```

Run with: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.xml`

**Option B: InstallUtil**
Compile a .NET assembly with a class that inherits `System.Configuration.Install.Installer`
and has `[RunInstaller(true)]`. Put your loader in the constructor or Install/Uninstall
methods.

Run with: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll`

**Option C: Process hollowing / injection into a whitelisted process**
If you have the capability, inject your CLR host shellcode into an already-running
whitelisted process. This bypasses app control entirely since the host process
is already approved.

### 4. Encrypted payload delivery improvements
- Don't use XOR with a short key — use AES-256 (the `AesDecrypt` in assembly_loader.cs
  handles this, port it to C++ or use a LOLBin approach)
- Derive the key from something environmental (hostname, domain SID, timestamp
  rounded to an interval) so the payload only decrypts on the intended target
- Consider chunking the encrypted blob across multiple delivery channels

### 5. Cleanup
- `UnloadDomain()` (already implemented)
- `SecureZeroMemory` the decrypted bytes (already implemented)
- Consider unhooking / repatching AMSI and ETW after execution to restore
  normal state and reduce forensic artifacts

## Detection timeline
1. **T+0**: Carbon Black App Control blocks unknown binary (if enforcing)
2. **T+0**: S1 static engine scans the PE on disk (or in memory if injected)
3. **T+100ms**: CLR loads → `clrjit.dll` load event → S1 behavioral alert
4. **T+200ms**: Assembly.Load → AMSI scan → S1 sees the cleartext assembly
5. **T+200ms**: ETW .NET runtime events fire → S1 sees assembly metadata
6. **T+300ms**: Assembly executes → behavioral analysis of what it does

Your mitigations need to hit points 1, 3, 4, and 5. Point 2 is handled by
the current approach (assembly never on disk). Point 6 depends on what
tool you're running.
