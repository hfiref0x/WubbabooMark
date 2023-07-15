/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       HANDLETRACE.CPP
*
*  VERSION:     1.00
*
*  DATE:        01 Jul 2023
*
*  Trace handler probe.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

VOID TraceHandle(
    _In_ PROBE_CONTEXT *Context,
    _In_ HANDLE Handle,
    _In_ PRTL_PROCESS_MODULES pvModules
)
{
    NTSTATUS ntStatus;
    PROCESS_HANDLE_TRACING_QUERY trace;

    RtlSecureZeroMemory(&trace, sizeof(trace));
    trace.Handle = Handle;

    ntStatus = NtQueryInformationProcess(NtCurrentProcess(), ProcessHandleTracing, &trace, sizeof(trace), NULL);
    if (!NT_SUCCESS(ntStatus)) {

        //
        // That's an error that should never happen. Raise wubbaboos.
        //

        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Error cannot query handle tracing"),
            (LPWSTR)TEXT("NtQueryInformationProcess"),
            (LPWSTR)TEXT("ProcessHandleTracing"));

        return;
    }

    for (ULONG i = 0; i < trace.TotalTraces; i++) {
        for (ULONG j = 0; j < PROCESS_HANDLE_TRACING_MAX_STACKS; j++) {

            ULONG moduleIndex = 0;
            PVOID stackAddress = trace.HandleTrace[i].Stacks[j];

            if (stackAddress == NULL)
                continue;

            if (!supFindModuleEntryByAddress(pvModules,
                stackAddress,
                &moduleIndex))
            {

                if ((ULONG_PTR)stackAddress >= Context->SystemRangeStart) {

                    SkReportUnknownCode((ULONG_PTR)stackAddress, 0);

                }
                else {


                    PVOID cookie = NULL;
                    ntStatus = LdrLockLoaderLock(0, NULL, &cookie);

                    if (NT_SUCCESS(ntStatus)) {

                        PLDR_DATA_TABLE_ENTRY entry;

                        ntStatus = LdrFindEntryForAddress(stackAddress, (PLDR_DATA_TABLE_ENTRY*)&entry);
                        if (!NT_SUCCESS(ntStatus)) {

                            SkReportUnknownCode((ULONG_PTR)stackAddress, 1);

                        }

                        LdrUnlockLoaderLock(0, cookie);
                    }
                    else {
                        SkReportNtCallRIP(ntStatus,
                            (LPWSTR)TEXT("Error cannot lock loader list"),
                            (LPWSTR)TEXT("LdrLockLoaderLock"),
                            NULL);
                    }
                }
            }
        }
    }
}

VOID TraceSectionHandle(
    _In_ PROBE_CONTEXT *Context,
    _In_ PRTL_PROCESS_MODULES pvModules
)
{
    NTSTATUS ntStatus;
    HANDLE sectionHandle = NULL, fileHandle = NULL;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING usName;
    IO_STATUS_BLOCK iost;

    RtlInitUnicodeString(&usName, L"\\systemroot\\system32\\ntdll.dll"); //lay in trap
    InitializeObjectAttributes(&obja, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    ntStatus = NtOpenFile(&fileHandle,
        SYNCHRONIZE | FILE_EXECUTE,
        &obja,
        &iost,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(ntStatus)) {
        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Error cannot open test file"),
            (LPWSTR)TEXT("NtOpenFile"),
            NULL);
        return;
    }

    RtlInitUnicodeString(&usName, L"\\RPC Control\\hui32");

    ntStatus = NtCreateSection(&sectionHandle,
        SECTION_ALL_ACCESS,
        &obja,
        NULL,
        PAGE_EXECUTE,
        SEC_IMAGE,
        fileHandle);

    if (NT_SUCCESS(ntStatus)) {

        TraceHandle(Context, sectionHandle, pvModules);

        NtClose(sectionHandle);
    }
    else {
        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Error cannot create test section"),
            (LPWSTR)TEXT("NtCreateSection"),
            NULL);
    }

    NtClose(fileHandle);
}

/*
* SkHandleTracing
*
* Purpose:
*
* Trace handles.
*
*/
BOOL SkHandleTracing(
    _In_ PPROBE_CONTEXT Context)
{
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    NTSTATUS ntStatus;
    PROCESS_HANDLE_TRACING_ENABLE traceEnable;
    PRTL_PROCESS_MODULES pvModules;

    traceEnable.Flags = 0;

    ntStatus = NtSetInformationProcess(NtCurrentProcess(),
        ProcessHandleTracing,
        &traceEnable,
        sizeof(traceEnable));

    if (!NT_SUCCESS(ntStatus)) {
        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Error cannot enable handle tracing"),
            (LPWSTR)TEXT("NtSetInformationProcess"),
            (LPWSTR)TEXT("ProcessHandleTracing"));
    }

    pvModules = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(FALSE, NULL);
    if (pvModules) {
        TraceSectionHandle(Context, pvModules);
        supHeapFree(pvModules);
    }

    //
    // Handle tracing will also raise exceptions on invalid handles.
    //

#ifndef _DEBUG
    BOOL bAnomalyDetected;

    __try {
        NtClose((HANDLE)0xBADC0FFEE);
        bAnomalyDetected = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        bAnomalyDetected = FALSE;
    }
#endif
    NtSetInformationProcess(NtCurrentProcess(), ProcessHandleTracing, &traceEnable, NULL);

#ifndef _DEBUG
    if (bAnomalyDetected) {
        SkReportInvalidHandleClosure(0);
    }
#endif
    return SkiGetAnomalyCount() == oldAnomalyCount;
}
