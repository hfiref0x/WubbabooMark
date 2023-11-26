/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       PROBES.CPP
*
*  VERSION:     1.00
*
*  DATE:        25 Nov 2023
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

ULONG g_cAnomalies = 0;

PROBE_CONTEXT* gProbeContext;

#define WINTRUST_INIT TEXT("Init->WinTrust")
#define CONTEXT_ALLOCATED TEXT("Init->Probe Context")

ULONG SkiGetAnomalyCount()
{
    return g_cAnomalies;
}

/*
* SkQueryNtdllBase
*
* Purpose:
*
* Find ntdll base by different methods and verify results.
*
*/
BOOL SkQueryNtdllBase(
    _In_ PPROBE_CONTEXT Context
)
{
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    ULONG_PTR nt1 = 0, nt2 = 0;
    WCHAR szDescription[MAX_TEXT_LENGTH];

    nt1 = (ULONG_PTR)GetModuleHandle(RtlNtdllName);
    nt2 = (ULONG_PTR)supGetImageBaseUnsafe((ULONG_PTR)NtCurrentPeb()->LoaderLock);

    if (nt1 != nt2) {

        SkiIncreaseAnomalyCount();

        StringCchPrintf(szDescription,
            RTL_NUMBER_OF(szDescription),
            L"LDR: 0x%llX, MEMORY: 0x%llX",
            nt1,
            nt2);

        supReportEvent(evtError,
            (LPWSTR)TEXT("NTDLL base is ambiguous"),
            szDescription,
            DT_NTDLL_IMAGEBASE_QUERY);
    }

    Context->NtDllBase = (PVOID)nt1;

    return (SkiGetAnomalyCount() == oldAnomalyCount);
}

NTSTATUS SkValidateClientInfo(
    _In_ TEB* Teb,
    _In_ PEB* Peb,
    _Inout_ PCLIENT_ID ClientId
)
{
    NTSTATUS ntStatus;
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES obja;
    HANDLE hObject = NULL;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength = 0;

    //
    // Validate TEB->ClientId.
    //
    cid = Teb->ClientId;
    *ClientId = cid;

    InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);

    ntStatus = NtOpenThread(&hObject, SYNCHRONIZE, &obja, &cid);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    if (SkIsThreadInformationTampered(TRUE, NtCurrentThread(), hObject))
        ntStatus = STATUS_INVALID_CID;

    NtClose(hObject);
    hObject = NULL;

    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    cid.UniqueThread = NULL;
    ntStatus = NtOpenProcess(&hObject, PROCESS_QUERY_LIMITED_INFORMATION, &obja, &cid);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    //
    // Validate PEB ptr for some stubborns.
    //
    ntStatus = NtQueryInformationProcess(hObject, 
        ProcessBasicInformation, 
        &pbi, 
        sizeof(pbi), 
        &returnLength);
    
    if (!NT_SUCCESS(ntStatus)) {
        NtClose(hObject);
        return ntStatus;
    }

    if (Peb != pbi.PebBaseAddress) {
        ntStatus = STATUS_CONFLICTING_ADDRESSES;
    }

    if (NT_SUCCESS(ntStatus)) {
        if (SkIsThreadInformationTampered(TRUE, NtCurrentProcess(), hObject))
            ntStatus = STATUS_INVALID_CID;
    }

    NtClose(hObject);

    if (!NT_SUCCESS(ntStatus))
        return ntStatus;


    //
    // Validate PEB->ImageBaseAddress.
    //
    PVOID pvImageBase = NULL;
    PUNICODE_STRING pusFileName;

    pusFileName = (PUNICODE_STRING)supGetProcessInfoVariableSize(ProcessImageFileName, &returnLength);
    if (pusFileName) {
        ntStatus = supMapImageNoExecute(pusFileName, &pvImageBase);
        if (NT_SUCCESS(ntStatus)) {
            ntStatus = NtAreMappedFilesTheSame(Peb->ImageBaseAddress, pvImageBase);
            NtUnmapViewOfSection(NtCurrentProcess(),
                pvImageBase);
        }
        supHeapFree(pusFileName);
    }
    return ntStatus;
}

/*
* SkCreateContext
*
* Purpose:
*
* Intiialize global pointers.
*
*/
PPROBE_CONTEXT SkCreateContext(
    _In_ PPROBE_SETTINGS Settings
)
{
    HRESULT hr;
    NTSTATUS ntStatus;
    ULONG dummy;
    HMODULE hModule;
    PPROBE_CONTEXT ctx;
    WCHAR szBuffer[MAX_PATH * 2];

    TEB* Teb = NtCurrentTeb();
    PEB* Peb = Teb->ProcessEnvironmentBlock;

    SIZE_T size;
    MEMORY_IMAGE_INFORMATION mii;

    ctx = (PPROBE_CONTEXT)supHeapAlloc(sizeof(PROBE_CONTEXT));
    if (ctx == NULL)
        return NULL;

    ntStatus = SkValidateClientInfo(Teb, Peb, &ctx->ClientId);
    if (!NT_SUCCESS(ntStatus)) {
        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Client information is tampered"),
            (LPWSTR)__FUNCTIONW__,
            NULL);
    }

    if (Peb->ProcessParameters->Flags & RTL_USER_PROC_DLL_REDIRECTION_LOCAL) {
        SkReportNtCallRIP(STATUS_INVALID_ADDRESS_COMPONENT,
            (LPWSTR)TEXT("Sxs DotLocal is enabled for client"),
            (LPWSTR)__FUNCTIONW__,
            NULL);
    }

    supIsProcessElevated(ctx->ClientId.UniqueProcess, &ctx->IsClientElevated);

    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        supHeapFree(ctx);

        SkReportComCallRIP(hr,
            (LPWSTR)TEXT("COM initialization failed"),
            (LPWSTR)__FUNCTIONW__,
            NULL);

        return NULL;
    }

    RtlGetNtVersionNumbers(&ctx->WindowsMajorVersion, &ctx->WindowsMinorVersion, NULL);
    ntStatus = supQueryNtOsInformation(&ctx->ReferenceNtBuildNumber, &ctx->NtOsBase);
    if (!NT_SUCCESS(ntStatus)) {
        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Failed to query NTOS information"),
            (LPWSTR)__FUNCTIONW__,
            NULL);
    }
    else {
        ctx->Win10FeaturePack = IS_WIN10_FEATURE_PACK_RANGE(ctx->ReferenceNtBuildNumber);
    }

    ctx->SelfBase = Peb->ImageBaseAddress;
    ntStatus = NtQueryVirtualMemory(NtCurrentProcess(),
        ctx->SelfBase,
        MemoryImageInformation,
        &mii,
        sizeof(mii),
        &size);

    if (!NT_SUCCESS(ntStatus)) {
        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Failed to query own image information"),
            (LPWSTR)__FUNCTIONW__,
            NULL);
    }
    else {
        ctx->SelfSize = mii.SizeOfImage;
    }

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szBuffer, TEXT("\\system32\\wintrust.dll"));
    hModule = LoadLibraryEx(szBuffer, NULL, 0);
    if (hModule != NULL) {
        ctx->WTGetSignatureInfo = (ptrWTGetSignatureInfo)GetProcAddress(hModule, "WTGetSignatureInfo");
    }

    ctx->Settings.Flags = Settings->Flags;

    ctx->SystemRangeStart = supQuerySystemRangeStart();
    if (ctx->SystemRangeStart == 0)
        if (ctx->WindowsMajorVersion > 8 ||
            (ctx->WindowsMajorVersion == 8 && ctx->WindowsMinorVersion == 1))
        {
            ctx->SystemRangeStart = 0xFFFF800000000000;
        }
        else {
            ctx->SystemRangeStart = 0xFFFF080000000000;
        }

    ntStatus = NtQuerySystemInformation(SystemBasicInformation,
        &ctx->SystemInfo,
        sizeof(SYSTEM_BASIC_INFORMATION),
        &dummy);

    if (!NT_SUCCESS(ntStatus)) {

        ctx->SystemInfo.MaximumUserModeAddress = 0x00007FFFFFFEFFFF;
        ctx->SystemInfo.MinimumUserModeAddress = 0x0000000000010000;

        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Failed to query system basic information"),
            (LPWSTR)TEXT("NtQuerySystemInformation"),
            (LPWSTR)TEXT("SystemBasicInformation"));

    }
    return ctx;
}

VOID SkDestroyContext(
    _In_ PPROBE_CONTEXT* Context)
{
    if ((*Context)->NtOsBase)
        NtUnmapViewOfSection(NtCurrentProcess(),
            (*Context)->NtOsBase);
    supHeapFree(*Context);
    *Context = NULL;
}

/*
* SkStartProbe
*
* Purpose:
*
* Thread for all probing routines.
*
*/
DWORD SkpProbeThread(
    _In_ LPVOID Parameter
)
{
    BOOL bWinTrustInitialized;
    DWORD dwWaitResult;
    DR_EVENT_TYPE evt = evtInformation;
    PROBE_STARTUP_INFO si = *(PROBE_STARTUP_INFO*)Parameter;
    WCHAR szBuffer[MAX_TEXT_LENGTH];

    dwWaitResult = WaitForSingleObject(gProbeWait, INFINITE);
    if (dwWaitResult == WAIT_OBJECT_0) {

        EnableMenuItem(GetMenu(si.MainWindow), ID_PROBES_SETTINGS, MF_BYCOMMAND | MF_DISABLED);
        EnableMenuItem(GetMenu(si.MainWindow), ID_PROBES_SAVETOFILE, MF_BYCOMMAND | MF_DISABLED);

        supStatusBarSetText(hwndStatusBar, 0, (LPCWSTR)TEXT("Scan in progress, please wait..."));

        szBuffer[0] = 0;
        SkiInitializeAnomalyCount();

        if (si.IsFirstRun == FALSE)
            ListView_DeleteAllItems(hwndList);

        if (gProbeContext) {
            SkDestroyContext(&gProbeContext);
        }

        gProbeContext = SkCreateContext(&si.Settings);
        if (gProbeContext == NULL) {
            REPORT_RIP(TEXT("Cannot allocate probe context, abort"));
            ExitThread(ERROR_NOT_ENOUGH_MEMORY);
        }
        else {
            REPORT_TEST_PASSED(CONTEXT_ALLOCATED);
        }

        bWinTrustInitialized = (gProbeContext->WTGetSignatureInfo != NULL);

        if (bWinTrustInitialized)
            REPORT_TEST_PASSED(WINTRUST_INIT);
        else
            REPORT_RIP(WINTRUST_INIT);

        //
        // Locate ntdll base.
        //
        if (SkQueryNtdllBase(gProbeContext))
            REPORT_TEST_PASSED(TEXT("Testing->NTDLL Base"));

        //
        // Run common tests.
        //
        if (gProbeContext->Settings.CommonChecks) {
            if (SkIsCustomKernelSignersPolicyEnabled())
                REPORT_TEST_PASSED(TEXT("Testing->Unsafe CI Policy"));
            if (SkCheckSystemDebugControl())
                REPORT_TEST_PASSED(TEXT("Testing->System Debug Control"));
            if (SkCheckDebugPrivileges())
                REPORT_TEST_PASSED(TEXT("Testing->DebugPrivileges"));
        }

        //
        // Walk for various wubbaboos.
        //
        if (bWinTrustInitialized) {
            if (gProbeContext->Settings.VerifyPEBLdr) {
                if (SkWalkPEB(gProbeContext))
                    REPORT_TEST_PASSED(TEXT("Testing->Loader List Modules"));
            }
            if (gProbeContext->Settings.VerifyLoadedDrivers) {
                if (SkWalkLoadedDrivers(gProbeContext))
                    REPORT_TEST_PASSED(TEXT("Testing->Loaded Drivers Verification"));
            }
        }

        //
        // Detect kernel wubbaboos.
        //
        if (gProbeContext->Settings.CheckDeviceObjects) {
            if (SkNoKernelWubbaboos())
                REPORT_TEST_PASSED(TEXT("Testing->Suspicious Device Objects"));
        }

        //
        // Verify Windows version information.
        //
        if (gProbeContext->Settings.VerifyWinVer) {
            if (SkVerifyWinVersion(gProbeContext))
                REPORT_TEST_PASSED(TEXT("Testing->Windows Version Information"));
        }

        //
        // Validate process lists.
        //
        if (gProbeContext->Settings.ValidateProcList) {
            if (SkValidateProcessList(gProbeContext))
                REPORT_TEST_PASSED(TEXT("Testing->Process List"));
        }

        //
        // Validate own thread list.
        //
        if (gProbeContext->Settings.ValidateThreadList) {
            if (SkValidateThreadList(gProbeContext))
                REPORT_TEST_PASSED(TEXT("Testing->Own Thread List"));
        }

        //
        // Analyze ntdll filtering.
        //
        if (gProbeContext->Settings.ValidateNtDllCopies) {
            if (SkLoadNtDllCopies())
                REPORT_TEST_PASSED(TEXT("Testing->NTDLL Mapping"));
        }

        //
        // Perform stack analysis.
        //
        if (gProbeContext->Settings.StackWalk) {
            if (SkStackWalk(gProbeContext))
                REPORT_TEST_PASSED(TEXT("Testing->Stack Walk"));
        }

        //
        // WS check.
        //
        if (gProbeContext->Settings.WsSetWalk) {
            if (SkWsSetWalk())
                REPORT_TEST_PASSED(TEXT("Testing->Process Working Set (Page)"));
        }

        if (gProbeContext->Settings.WsSetWatch) {
            if (SkWsSetWatch(gProbeContext))
                REPORT_TEST_PASSED(TEXT("Testing->Process Working Set (Watch)"));
        }

        //
        // Perform syscall tests.
        //
        if (gProbeContext->Settings.CheckNtOsSyscalls) {
            if (SkTestSyscalls(gProbeContext))
                REPORT_TEST_PASSED(TEXT("Testing->NTOS System Call Verification"));
        }
        if (gProbeContext->Settings.CheckWin32kSyscalls) {
            if (SkValidateWin32uSyscalls(gProbeContext))
                REPORT_TEST_PASSED(TEXT("Testing->Win32k System Call Verification"));
        }

        //
        // Check debugging.
        //
        if (gProbeContext->Settings.CheckDebug) {
            if (SkCheckDebug(gProbeContext->NtDllBase))
                REPORT_TEST_PASSED(TEXT("Testing->Debugger Detection"));
        }

        //
        // Debug objects check.
        //
        if (gProbeContext->Settings.CheckHandles) {
            if (SkCheckHandles(gProbeContext))
                REPORT_TEST_PASSED(TEXT("Testing->NT Object Handles"));
        }

        //
        // Walk NtUser/NtGdi tables.
        // This is parsing of a new format available since W10 RS4.
        //
        if (gProbeContext->WindowsMajorVersion >= 10) {
            if (gProbeContext->Settings.WalkUserHandleTable) {
                if (SkUserHandleTableWalk(gProbeContext))
                    REPORT_TEST_PASSED(TEXT("Testing->UserHandleTable (Win10 RS4+)"));
            }
            if (gProbeContext->Settings.WalkGdiSharedHandleTable) {
                if (SkGdiSharedHandleTableWalk(gProbeContext))
                    REPORT_TEST_PASSED(TEXT("Testing->GdiSharedHandleTable (Win10 RS4+)"));
            }
        }

        //
        // Test boot configuration data. Requires elevated client.
        //
        if (gProbeContext->Settings.CheckBootConfiguration) {
            if (gProbeContext->IsClientElevated) {
                if (SkTestBootConfiguration())
                    REPORT_TEST_PASSED(TEXT("Testing->BootConfigurationData"));
            }
            else {
                REPORT_TEST_SKIPPED(TEXT("BootConfigurationData Test Skipped -> Elevation Required"));
            }

        }

        //
        // Test handle tracing.
        //
        if (gProbeContext->Settings.HandleTracing) {
            if (SkHandleTracing(gProbeContext))
                REPORT_TEST_PASSED(TEXT("Testing->Handle Tracing"));
        }

        //
        // Scan process memory.
        //
        if (gProbeContext->Settings.CheckProcessMemory) {
            if (SkCheckProcessMemory(gProbeContext))
                REPORT_TEST_PASSED(TEXT("Testing->Process Memory Regions"));
        }

        ULONG count = SkiGetAnomalyCount();
        if (count == 0) {
            _strcpy(szBuffer, TEXT("No Wubbaboos are detected during tests (｀□′)╯┴┴"));
        }
        else {
            evt = evtWarning;
            StringCchPrintf(szBuffer, RTL_NUMBER_OF(szBuffer),
                TEXT("Number of Wubbaboos detected: %lu  ( ｡ᵘ ᵕ ᵘ ｡)"),
                count);
        }

        supReportEvent(evt,
            szBuffer,
            NULL,
            NULL);

        supStatusBarSetText(hwndStatusBar, 0, szBuffer);

        ReleaseMutex(gProbeWait);
        EnableMenuItem(GetMenu(si.MainWindow), ID_PROBES_SAVETOFILE, MF_BYCOMMAND | MF_ENABLED);
        EnableMenuItem(GetMenu(si.MainWindow), ID_PROBES_SETTINGS, MF_BYCOMMAND | MF_ENABLED);
    }

    ExitThread(ERROR_SUCCESS);
}

/*
* SkStartProbe
*
* Purpose:
*
* Execute probing thread.
*
*/
VOID SkStartProbe(
    _In_ PROBE_STARTUP_INFO* StartupInfo
)
{
    DWORD threadId;

    if (StartupInfo->IsFirstRun)
    {
        if (FAILED(CoInitializeSecurity(NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_SECURE_REFS,
            NULL)))
        {
            REPORT_RIP(TEXT("Could not initialize COM security"));
            return;
        }
    }

    HANDLE threadHandle = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)SkpProbeThread,
        (PVOID)StartupInfo, 0, &threadId);

    if (threadHandle) CloseHandle(threadHandle);
}
