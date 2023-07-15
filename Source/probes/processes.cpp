/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       PROCESSES.CPP
*
*  VERSION:     1.00
*
*  DATE:        01 Jul 2023
*
*  Process list probes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

typedef struct _PS_LIST {
    struct _PS_LIST* Prev;
    ULONG UniqueProcessId;
    ULONG ParentProcessId;
    WCHAR szName[MAX_PATH];
} PS_LIST, * PPS_LIST;

//
// MSDN rip-on
//
#define SDB_MAX_EXES 16
#define SDB_MAX_LAYERS 8
#define SDB_MAX_SDBS 16

typedef DWORD TAGREF;

typedef struct tagSDBQUERYRESULT {
    TAGREF atrExes[SDB_MAX_EXES];
    DWORD  adwExeFlags[SDB_MAX_EXES];
    TAGREF atrLayers[SDB_MAX_LAYERS];
    DWORD  dwLayerFlags;
    TAGREF trApphelp;
    DWORD  dwExeCount;
    DWORD  dwLayerCount;
    GUID   guidID;
    DWORD  dwFlags;
    DWORD  dwCustomSDBMap;
    GUID   rgGuidDB[SDB_MAX_SDBS];
} SDBQUERYRESULT, * PSDBQUERYRESULT;
//
// MSDN rip-off
//

//
// Totally opaque structure, changes between Win versions, head remains same, 
// everything else is not - use with caution. Primary source of RE is apphelp.dll and leaked symbols, 
// ignore various trash like reactos, shims wasn't in win2k source so they don't give a clue about it.
//
#define APPCOMPAT_EXE_DATA_MAGIC 0xAC0DEDAB

typedef struct _APP_COMPAT_EXE_INFO {
    WCHAR szShimEngine[MAX_PATH];       //+0x0
    ULONG cbSize;                       //+0x208
    ULONG dwMagic;                      //+0x20C
    ULONG dwFlags;                      //+0x210
    ULONG dwMachine;                    //+0x214
    SDBQUERYRESULT SdbQueryResult;      //+0x218
    BYTE ApphelpDebug[1024];            //as it was on w8
    BYTE Undefined[0x358];
    ULONG dwParentProcessId;
    WCHAR szParentImageName[MAX_PATH];
    //incomplete
} APP_COMPAT_EXE_INFO, * PAPP_COMPAT_EXE_INFO;

//
// Copied from ScyllaHide with brave and courage and then improved to actually work.
// We just look for what they protect - very comfortable!
//
CONST WCHAR* WubbabooProcessList[] =
{
  L"ollydbg",
  L"ida.exe",
  L"ida64.exe",
  L"idag.exe",
  L"idag64.exe",
  L"idaw.exe",
  L"idaw64.exe",
  L"idaq.exe",
  L"idaq64.exe",
  L"idau.exe",
  L"idau64.exe",
  L"scylla",
  L"protection_id.exe",
  L"x64dbg",
  L"x32dbg",
  L"windbg",
  L"reshacker",
  L"ImportREC",
  L"immunitydebugger",
  L"devenv.exe",
  L"Procmon",
  L"apimonitor",
  L"cheatengine"
};

/*
* SkIsParentProcessExist
*
* Purpose:
*
* Find parent process in API query result.
*
*/
BOOL SkIsParentProcessExist(
    _In_ PVOID ProcessList,
    _In_ HANDLE ParentProcessId,
    _In_opt_ LPWSTR Description
)
{
    WCHAR szBuffer[MAX_TEXT_LENGTH];

    if (NULL != supProcessEntryByProcessId(ParentProcessId, ProcessList)) {
        return TRUE;
    }
    else {
        SkiIncreaseAnomalyCount();

        StringCchPrintf(szBuffer,
            RTL_NUMBER_OF(szBuffer),
            TEXT("Process with id %lu doesn't exist in the native query"),
            HandleToUlong(ParentProcessId));

        supReportEvent(evtDetection,
            szBuffer,
            Description,
            DT_HIDDENPROCESS);

        return FALSE;
    }
}

/*
* SkCheckBadProcess
*
* Purpose:
*
* Find process name substring in a blacklist.
*
*/
BOOL SkCheckBadProcess(
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING ProcessName,
    _In_ PS_SCAN_TYPE ScanType
)
{
    BOOL bResult = FALSE;
    WCHAR szBuffer[MAX_TEXT_LENGTH * 2];
    LPWSTR lpScanType;
    UNICODE_STRING usName;

    for (ULONG i = 0; i < RTL_NUMBER_OF(WubbabooProcessList); i++) {

        RtlInitUnicodeString(&usName, WubbabooProcessList[i]);
        SIZE_T pos = supFindUnicodeStringSubString(ProcessName, &usName);
        if (pos != ULLONG_MAX) {

            bResult = TRUE;

            SkiIncreaseAnomalyCount();

            switch (ScanType) {
            case ScanTypeWMI:
                lpScanType = (LPWSTR)TEXT("WMI Query");
                break;
            case ScanTypeAppCompat:
                lpScanType = (LPWSTR)TEXT("AppCompat Query");
                break;
            case ScanTypeNative:
            default:
                lpScanType = (LPWSTR)TEXT("Native Query");
                break;
            }

            StringCchPrintf(szBuffer,
                RTL_NUMBER_OF(szBuffer),
                TEXT("Process %lu with name substring \"%ws\" (%ws)"),
                ProcessId,
                WubbabooProcessList[i],
                lpScanType);

            supReportEvent(evtDetection,
                szBuffer,
                ProcessName->Buffer,
                DT_BAD_PROCESS_NAME);
        }

    }

    return bResult;
}

/*
* SkiAnyWubbaboosInProcessList
*
* Purpose:
*
* Find known wubbaboos by their names.
*
*/
VOID SkiAnyWubbaboosInProcessList(
    _In_ PPS_LIST List
)
{
    PS_LIST* currentEntry, * nextEntry;
    UNICODE_STRING usProcessName;

    currentEntry = List;

    while (currentEntry) {
        nextEntry = currentEntry->Prev;
        RtlInitUnicodeString(&usProcessName, currentEntry->szName);
        SkCheckBadProcess(currentEntry->UniqueProcessId, &usProcessName, ScanTypeWMI);
        currentEntry = nextEntry;
    }
}

/*
* SkiCheckConsoleHost
*
* Purpose:
*
* Query process console host and check it against list of processes from Windows API.
*
*/
VOID SkiCheckConsoleHost(
    _In_ PVOID ProcessList
)
{
    HANDLE consolePID = 0;

    if (NT_SUCCESS(supGetConsoleHostForSelf(&consolePID))) {

        consolePID = (HANDLE)((ULONG_PTR)consolePID & ~3);

        SkIsParentProcessExist(ProcessList,
            consolePID,
            (LPWSTR)TEXT("ProcessConsoleHostProcess"));

    }
}

/*
* SkiCheckAppCompat
*
* Purpose:
*
* Parse AppCompat data from PEB.
*
*/
VOID SkiCheckAppCompat(
    _In_ PVOID ProcessList
)
{
    PEB* peb = NtCurrentPeb();
    PAPP_COMPAT_EXE_INFO pAppCompatExe = (PAPP_COMPAT_EXE_INFO)peb->pShimData;

    if (pAppCompatExe) {

        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T size;
        NTSTATUS ntStatus;

        ntStatus = NtQueryVirtualMemory(NtCurrentProcess(),
            pAppCompatExe,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &size);

        if (NT_SUCCESS(ntStatus)) {

            size = mbi.RegionSize;
            if ((pAppCompatExe->dwMagic == APPCOMPAT_EXE_DATA_MAGIC) &&
                (sizeof(APP_COMPAT_EXE_INFO) <= size) &&
                (pAppCompatExe->cbSize <= size))
            {
                PWCH p, pp = NULL;
                UNICODE_STRING usProcName;

                p = pAppCompatExe->szParentImageName;
                while (*p) {
                    if (*p++ == (WCHAR)'\\') {
                        pp = p;
                    }
                }

                RtlInitUnicodeString(&usProcName, pp);
                SkCheckBadProcess(pAppCompatExe->dwParentProcessId,
                    &usProcName,
                    ScanTypeAppCompat);

                SkIsParentProcessExist(ProcessList,
                    UlongToHandle(pAppCompatExe->dwParentProcessId),
                    pp);

            }
        }
        else {
            SkReportNtCallRIP(ntStatus,
                (LPWSTR)TEXT("Cannot query process AppCompat memory"),
                (LPWSTR)TEXT("NtQueryVirtualMemory"),
                (LPWSTR)TEXT("MemoryBasicInformation"));
        }
    }
}

/*
* SkiBuildProcessListWMI
*
* Purpose:
*
* Query process list with WMI RPC calls.
*
*/
BOOL SkiBuildProcessListWMI(
    _In_ HANDLE HeapHandle,
    _Out_ PPS_LIST* List
)
{
    BOOL bResult = FALSE;
    HRESULT hr = S_OK, hr2 = S_OK, hr3 = S_OK;
    IWbemLocator* WbemLocator = NULL;
    IWbemServices* WbemServices = NULL;
    IEnumWbemClassObject* enumWbem = NULL;
    IWbemClassObject* result = NULL;

    ULONG returnedCount = 0;

    BSTR bstrServer = NULL;
    BSTR bstrQuery = NULL, bstrQueryLanguage = NULL;
    VARIANT ProcessId, ProcessName, ParentPID;

    PS_LIST* psEntry;

    *List = NULL;

    do {

        VariantInit(&ProcessId);
        VariantInit(&ProcessName);
        VariantInit(&ParentPID);

        bstrServer = SysAllocString(L"ROOT\\CIMV2"); //CIMWin32
        bstrQuery = SysAllocString(L"SELECT * FROM Win32_Process");
        bstrQueryLanguage = SysAllocString(L"WQL");

        if ((bstrServer == NULL) ||
            (bstrQuery == NULL) ||
            (bstrQueryLanguage == NULL))
        {
            SkReportComCallRIP(E_FAIL,
                (LPWSTR)TEXT("Cannot allocate memory for string"),
                (LPWSTR)__FUNCTIONW__,
                NULL);
            break;
        }

        hr = CoCreateInstance(CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID*)&WbemLocator);

        if (FAILED(hr)) {
            SkReportComCallRIP(hr,
                (LPWSTR)TEXT("Cannot create locator instance"),
                (LPWSTR)__FUNCTIONW__,
                NULL);
            break;
        }

        hr = WbemLocator->ConnectServer(bstrServer,
            NULL,
            NULL,
            NULL,
            0,
            NULL,
            NULL,
            &WbemServices);

        if (FAILED(hr)) {
            SkReportComCallRIP(hr,
                (LPWSTR)TEXT("Cannot connect CIMV2 server"),
                (LPWSTR)__FUNCTIONW__,
                NULL);
            break;
        }

        hr = WbemServices->ExecQuery(bstrQueryLanguage,
            bstrQuery,
            WBEM_FLAG_FORWARD_ONLY,
            NULL,
            &enumWbem);
        if (FAILED(hr)) {
            SkReportComCallRIP(hr,
                (LPWSTR)TEXT("Failed to execute query"),
                (LPWSTR)__FUNCTIONW__,
                NULL);
            break;
        }

        ULONG cProc = 0;

        while ((hr = enumWbem->Next(WBEM_INFINITE, 1, &result, &returnedCount)) == S_OK) {

            hr3 = result->Get(L"ParentProcessId", 0, &ParentPID, 0, 0);
            hr2 = result->Get(L"Name", 0, &ProcessName, 0, 0);
            hr = result->Get(L"ProcessId", 0, &ProcessId, 0, 0);
            if (SUCCEEDED(hr) && SUCCEEDED(hr2) && SUCCEEDED(hr3)) {

                psEntry = (PS_LIST*)RtlAllocateHeap(HeapHandle, HEAP_ZERO_MEMORY, sizeof(PS_LIST));
                if (psEntry) {

                    psEntry->UniqueProcessId = ProcessId.ulVal;
                    psEntry->Prev = *List;
                    psEntry->ParentProcessId = ParentPID.ulVal;

                    StringCchCopy(psEntry->szName,
                        RTL_NUMBER_OF(psEntry->szName),
                        ProcessName.bstrVal);

                    cProc += 1;
                }

                *List = psEntry;
            }

            VariantClear(&ProcessId);
            VariantClear(&ProcessName);
            VariantClear(&ParentPID);

            result->Release();
        }

        bResult = (cProc > 0);

    } while (FALSE);

    if (enumWbem) enumWbem->Release();
    if (WbemServices) WbemServices->Release();
    if (WbemLocator) WbemLocator->Release();

    if (bstrServer) SysFreeString(bstrServer);
    if (bstrQueryLanguage) SysFreeString(bstrQueryLanguage);
    if (bstrQuery) SysFreeString(bstrQuery);

    return bResult;
}

/*
* SkpGetProcessEntrySize
*
* Purpose:
*
* Calculate actual process entry size.
*
*/
ULONG SkpGetProcessEntrySize(
    _In_ PROBE_CONTEXT* Context,
    _In_ PSYSTEM_PROCESS_INFORMATION Entry
)
{
    ULONG entrySize;

    entrySize = FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, Threads);
    entrySize += Entry->ImageName.MaximumLength;
    entrySize += (Entry->ThreadCount * sizeof(SYSTEM_THREAD_INFORMATION));

    if (Context->WindowsMajorVersion >= 10) {
        //
        // Always present in enumeration even if not requested in Win10 and above.
        // Doesn't exist pre 8.1
        //
        entrySize += sizeof(SYSTEM_PROCESS_INFORMATION_EXTENSION);
    }
    return entrySize;
}

/*
* SkValidateProcessList
*
* Purpose:
*
* Do snapshots of running processes using different API and compare results.
*
*/
BOOL SkValidateProcessList(
    _In_ PROBE_CONTEXT* Context
)
{
    BOOL bWmiListWasReady = FALSE;
    ULONG oldAnomalyCount = SkiGetAnomalyCount(), returnedLength = 0, entrySize;
    PVOID processList;
    PS_LIST* currentEntry, * nextEntry, * WMIList = NULL;
    HANDLE enumHeap;
    ULONG_PTR parentPID = 0;
    ULONG nextEntryDelta = 0, prevEntryDelta = 0;
    ULONG currentPID = HandleToUlong(Context->ClientId.UniqueProcess);
    PROCESS_BASIC_INFORMATION pbi;

    union {
        PSYSTEM_PROCESS_INFORMATION Process;
        PBYTE ListRef;
    } NativeList;

    //
    // At first, walk list as usual.
    //
    __try {
        processList = supGetSystemInfo(SystemProcessInformation, &returnedLength);
        if (processList) {

            NativeList.ListRef = (PBYTE)processList;
            do {

                NativeList.ListRef += nextEntryDelta;
                prevEntryDelta = nextEntryDelta;

                SkCheckBadProcess(HandleToUlong(NativeList.Process->UniqueProcessId),
                    &NativeList.Process->ImageName, ScanTypeNative);

                //
                // Detect entry corruption.
                //
                entrySize = SkpGetProcessEntrySize(Context, NativeList.Process);
                nextEntryDelta = NativeList.Process->NextEntryDelta;
                if (nextEntryDelta && entrySize != nextEntryDelta) {
                    SkReportProcListCorruption(nextEntryDelta, entrySize);
                }

            } while (nextEntryDelta);

            //
            // Check against console host information.
            //
            SkiCheckConsoleHost(processList);

            //
            // Query AppCompat data.
            //
            SkiCheckAppCompat(processList);

            supHeapFree(processList);
            processList = NULL;
        }
        else {
            SkReportNtCallRIP(STATUS_UNSUCCESSFUL,
                (LPWSTR)TEXT("Cannot query process list"),
                (LPWSTR)TEXT("NtQuerySystemInformation"),
                (LPWSTR)TEXT("SystemProcessInformation"));
        }

        //
        // Find detour/instrumentation hidden processes.
        //
        enumHeap = (HANDLE)RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
        if (enumHeap) {

            bWmiListWasReady = SkiBuildProcessListWMI(enumHeap, &WMIList);
            if (bWmiListWasReady) {

                processList = supGetSystemInfo(SystemProcessInformation, NULL);
                if (processList) {

                    currentEntry = WMIList;

                    while (currentEntry) {
                        nextEntry = currentEntry->Prev;

                        if (parentPID == 0 && currentEntry->UniqueProcessId == currentPID)
                            parentPID = currentEntry->ParentProcessId;

                        SkIsParentProcessExist(processList,
                            UlongToHandle(currentEntry->UniqueProcessId),
                            currentEntry->szName);

                        currentEntry = nextEntry;
                    }

                    supHeapFree(processList);
                }
                else {
                    SkReportNtCallRIP(STATUS_UNSUCCESSFUL,
                        (LPWSTR)TEXT("Cannot query process list"),
                        (LPWSTR)TEXT("NtQuerySystemInformation"),
                        (LPWSTR)TEXT("SystemProcessInformation"));
                }
            }
            else {
                SkiIncreaseAnomalyCount();
                supReportEvent(evtDetection,
                    (LPWSTR)TEXT("WMI query failed"),
                    NULL,
                    DT_WMIQUERY);
            }

            SkiAnyWubbaboosInProcessList(WMIList);
            RtlDestroyHeap(enumHeap);
        }
        else {
            SkReportNtCallRIP(STATUS_UNSUCCESSFUL,
                (LPWSTR)TEXT("Cannot create enumeration heap"),
                (LPWSTR)TEXT("RtlCreateHeap"),
                DT_WMIQUERY);
        }

        //
        // Parent process faking check.
        //
        if (bWmiListWasReady) {
            ULONG length;
            NTSTATUS ntStatus = NtQueryInformationProcess(NtCurrentProcess(),
                ProcessBasicInformation,
                &pbi,
                sizeof(PROCESS_BASIC_INFORMATION),
                &length);

            if (!NT_SUCCESS(ntStatus)) {

                SkReportNtCallRIP(ntStatus,
                    (LPWSTR)TEXT("Failed to query process basic information"),
                    (LPWSTR)TEXT("NtQueryInformationProcess"),
                    NTQIP_PBI_QUERY);

            }
            else {
                if (pbi.InheritedFromUniqueProcessId != parentPID) {

                    SkReportParentProcessMismatch(pbi.InheritedFromUniqueProcessId,
                        parentPID);

                }
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SkReportNtCallRIP(STATUS_ACCESS_VIOLATION,
            (LPWSTR)TEXT("Access violation while parsing process list"),
            (LPWSTR)TEXT("SkValidateProcessList"),
            NULL);
    }
    return (SkiGetAnomalyCount() == oldAnomalyCount);
}
