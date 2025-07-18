/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023 - 2025
*
*  TITLE:       MEMORY.CPP
*
*  VERSION:     1.10
*
*  DATE:        13 Jul 2025
*
*  Stack probes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#define MAX_WATCH_COUNT 256
#define NTQVM_MAX_BUFFER_LENGTH (256)*(256)*(1024)

BOOL SkpProbeForExecutable(ULONG_PTR addr)
{
    __volatile PFEFN probefn;

    __try {
        for (;; ++addr)
            if (0xc3 == *(PBYTE)addr) {
                probefn = (PFEFN)addr;
                probefn();
                return TRUE;
            }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return FALSE;
}

VOID SkiCheckMemoryWsBlock(
    _In_ PMEMORY_WORKING_SET_BLOCK WsBlock
)
{
    WCHAR szBuffer[MAX_TEXT_LENGTH];
    ULONG_PTR address = WsBlock->VirtualPage * PAGE_SIZE;

    if (WsBlock->Shared == 0 || WsBlock->ShareCount == 0) {
        SkiIncreaseAnomalyCount();
        StringCchPrintf(szBuffer,
            RTL_NUMBER_OF(szBuffer),
            TEXT("0x%llX"),
            address);

        supReportEventEx(evtDetection,
            (LPWSTR)TEXT("Suspicious memory page"),
            szBuffer,
            DT_INJECTEDCODE,
            address,
            TRUE);
    }
}

/*
* SkWsSetWalk
*
* Purpose:
*
* Check suspicious entries in a working set list.
*
*/
BOOL SkWsSetWalk(
    VOID
)
{
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    NTSTATUS ntStatus;
    ULONG_PTR i;
    PMEMORY_WORKING_SET_INFORMATION pws = NULL;
    PMEMORY_WORKING_SET_BLOCK pwsBlock;
    SIZE_T bufferSize = PAGE_SIZE;

    pws = (PMEMORY_WORKING_SET_INFORMATION)supHeapAlloc(bufferSize);

    while ((ntStatus = NtQueryVirtualMemory(
        NtCurrentProcess(),
        NULL,
        MemoryWorkingSetInformation,
        pws,
        bufferSize,
        &bufferSize)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        supHeapFree(pws);
        bufferSize <<= 1;

        if (bufferSize > NTQVM_MAX_BUFFER_LENGTH) {
            pws = NULL;
            ntStatus = STATUS_TOO_MANY_SECRETS;
            break;
        }

        pws = (PMEMORY_WORKING_SET_INFORMATION)supHeapAlloc((SIZE_T)bufferSize);
        if (pws == NULL) {
            ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
            break;
        }
    }

    if (pws == NULL) {
        SkReportNtCallRIP(STATUS_MEMORY_NOT_ALLOCATED,
            (LPWSTR)TEXT("Cannot allocate virtual memory"),
            (LPWSTR)TEXT("supHeapAlloc"),
            NULL);
        return FALSE;
    }

    if (!NT_SUCCESS(ntStatus)) {

        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Cannot query virtual memory"),
            (LPWSTR)TEXT("NtQueryVirtualMemory"),
            (LPWSTR)TEXT("MemoryWorkingSetInformation"));
   
    } else {

        for (i = 0; i < pws->NumberOfEntries; i++) {

            pwsBlock = &pws->WorkingSetInfo[i];

            if ((pwsBlock->Protection == MM_EXECUTE) ||
                (pwsBlock->Protection == MM_EXECUTE_READWRITE) ||
                (pwsBlock->Protection == MM_EXECUTE_WRITECOPY))
            {
                SkiCheckMemoryWsBlock(pwsBlock);
            }
        }

    }

    supHeapFree(pws);

    return (SkiGetAnomalyCount() == oldAnomalyCount);
}

/*
* SkStackWalk
*
* Purpose:
*
* Walk entire stack of suspicious values.
*
*/
BOOL SkStackWalk(
    _In_ PPROBE_CONTEXT Context
)
{
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    ULONG_PTR maxAppAddress, minAppAddress;
    ULONG_PTR myRsp, p, lowRsp = 0, highRsp = 0;
    __volatile ULONG_PTR x;

    MEMORY_BASIC_INFORMATION mi;
    WCHAR szBuffer[MAX_TEXT_LENGTH];

    maxAppAddress = Context->SystemInfo.MaximumUserModeAddress;
    minAppAddress = Context->SystemInfo.MinimumUserModeAddress;

    myRsp = (ULONG_PTR)_AddressOfReturnAddress() & ~(PAGE_SIZE - 1);
    lowRsp = myRsp;

    for (p = myRsp; p > 0; p -= PAGE_SIZE) {

        __try {
            x = *(ULONG_PTR*)p;
            *(ULONG_PTR*)p = x;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        lowRsp = p;
    }

    for (p = myRsp; p < maxAppAddress; p += PAGE_SIZE) {

        __try {
            PUSH_DISABLE_WARNING(6011)
                x = *(ULONG_PTR*)p;
            POP_DISABLE_WARNING(6011)
                * (ULONG_PTR*)p = x;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        highRsp = p;
    }
    highRsp += PAGE_SIZE - sizeof(ULONG_PTR);

    for (p = highRsp; p >= lowRsp; p -= sizeof(ULONG_PTR)) {

        x = *(ULONG_PTR*)p;
        if ((x >= minAppAddress) && (x < maxAppAddress)) {

            // if (ProbeForExecutable(x)) {

            SIZE_T length;

            if (NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(),
                (PVOID)x,
                MemoryBasicInformation,
                &mi,
                sizeof(mi),
                &length)))
            {
                if ((mi.Protect == PAGE_EXECUTE) ||
                    (mi.Protect == PAGE_EXECUTE_READ) ||
                    (mi.Protect == PAGE_EXECUTE_READWRITE) ||
                    (mi.Protect == PAGE_EXECUTE_WRITECOPY))
                {
                    PLDR_DATA_TABLE_ENTRY pvTableEntry = NULL;

                    if (!NT_SUCCESS(LdrFindEntryForAddress((PVOID)x, (PLDR_DATA_TABLE_ENTRY*)&pvTableEntry))) {

                        SkiIncreaseAnomalyCount();

                        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));

                        StringCchPrintf(szBuffer, RTL_NUMBER_OF(szBuffer),
                            TEXT("0x%llX"),
                            x);

                        supReportEventEx(evtDetection,
                            (LPWSTR)TEXT("There are traces of injected code in a call stack"),
                            szBuffer,
                            DT_INJECTEDCODE,
                            x,
                            TRUE);

                    }
                }
            }
        }
    }

    return (SkiGetAnomalyCount() == oldAnomalyCount);
}

BOOL SkiVerifyWSValueUserMode(
    _In_ PVOID WsValue
)
{
    NTSTATUS ntStatus;
    PLDR_DATA_TABLE_ENTRY entry;
    WCHAR szText[MAX_TEXT_LENGTH];
    MEMORY_BASIC_INFORMATION mi;

    SIZE_T length;

    if (NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(),
        WsValue,
        MemoryBasicInformation,
        &mi,
        sizeof(mi),
        &length)))
    {
        if ((mi.Protect == PAGE_EXECUTE) ||
            (mi.Protect == PAGE_EXECUTE_READ) ||
            (mi.Protect == PAGE_EXECUTE_READWRITE) ||
            (mi.Protect == PAGE_EXECUTE_WRITECOPY))
        {
            ntStatus = LdrFindEntryForAddress(WsValue, (PLDR_DATA_TABLE_ENTRY*)&entry);
            if (!NT_SUCCESS(ntStatus)) {

                SkiIncreaseAnomalyCount();

                RtlSecureZeroMemory(&szText, sizeof(szText));

                StringCchPrintf(szText,
                    RTL_NUMBER_OF(szText),
                    TEXT("0x%llX"),
                    (ULONG_PTR)WsValue);

                supReportEventEx(evtDetection,
                    (LPWSTR)TEXT("There are traces of injected code in a working set"),
                    szText,
                    DT_INJECTEDCODE,
                    (ULONG_PTR)WsValue,
                    TRUE);

                return FALSE;
            }
        }
    }

    return TRUE;
}

/*
* SkWsSetWatch
*
* Purpose:
*
* Check suspicious entries in a working set by a watch.
*
*/
BOOL SkWsSetWatch(
    _In_ PPROBE_CONTEXT Context
)
{
    NTSTATUS ntStatus;
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    PROCESS_WS_WATCH_INFORMATION_EX* pWatchInfo = NULL;
    ULONG_PTR maxAppAddress = 0;

    maxAppAddress = Context->SystemInfo.MaximumUserModeAddress;

    do {

        //
        // Set watch.
        //
        ntStatus = NtSetInformationProcess(
            NtCurrentProcess(),
            ProcessWorkingSetWatchEx,
            NULL,
            0);

        if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_PORT_ALREADY_SET) {

            SkReportNtCallRIP(ntStatus,
                (LPWSTR)TEXT("Failed to enable WS watch"),
                (LPWSTR)TEXT("NtSetInformationProcess"),
                DT_WSSET_FAILED);

            break;
        }

        //
        // Empty WS.
        //
        ntStatus = supEmptyWorkingSet();
        if (!NT_SUCCESS(ntStatus)) {

            SkReportNtCallRIP(ntStatus,
                (LPWSTR)TEXT("Failed to empty process working set"),
                (LPWSTR)TEXT("NtSetInformationProcess"),
                DT_WSSET_FAILED);

            break;
        }

        //
        // Watch changes.
        //
        SIZE_T size = 256 * sizeof(PROCESS_WS_WATCH_INFORMATION_EX);
        ULONG returnLength;

        pWatchInfo = (PROCESS_WS_WATCH_INFORMATION_EX*)supHeapAlloc(size);
        if (pWatchInfo == NULL) {

            SkReportNtCallRIP(STATUS_MEMORY_NOT_ALLOCATED,
                (LPWSTR)TEXT("Failed to allocate memory"),
                (LPWSTR)TEXT("RtlAllocateHeap"),
                DT_WSSET_FAILED);

            break;
        }

        ntStatus = NtQueryInformationProcess(
            NtCurrentProcess(),
            ProcessWorkingSetWatch,
            (PVOID*)pWatchInfo,
            (ULONG)size,
            &returnLength);

        if (ntStatus == STATUS_BUFFER_TOO_SMALL) {
            supHeapFree(pWatchInfo);

            size = (256 * sizeof(PROCESS_WS_WATCH_INFORMATION_EX)) + returnLength;

            pWatchInfo = (PROCESS_WS_WATCH_INFORMATION_EX*)supHeapAlloc(size);

            ntStatus = NtQueryInformationProcess(
                NtCurrentProcess(),
                ProcessWorkingSetWatch,
                (PVOID*)pWatchInfo,
                (ULONG)size,
                &returnLength);
        }

        if (!NT_SUCCESS(ntStatus)) {

            SkReportNtCallRIP(ntStatus,
                (LPWSTR)TEXT("Failed to query process working set change"),
                (LPWSTR)TEXT("NtQueryInformationProcess"),
                DT_WSSET_FAILED);

            break;
        }

        //
        // Find wubbaboos.
        //
        PVOID cookie;
        ntStatus = LdrLockLoaderLock(0, NULL, &cookie);
        if (NT_SUCCESS(ntStatus)) {

            for (ULONG i = 0; i < MAX_WATCH_COUNT; i++) {

                if (pWatchInfo[i].BasicInfo.FaultingPc && pWatchInfo[i].BasicInfo.FaultingVa) {

                    if ((ULONG_PTR)pWatchInfo[i].BasicInfo.FaultingPc < maxAppAddress)
                        SkiVerifyWSValueUserMode(pWatchInfo[i].BasicInfo.FaultingPc);

                    if ((ULONG_PTR)pWatchInfo[i].BasicInfo.FaultingVa < maxAppAddress)
                        SkiVerifyWSValueUserMode(pWatchInfo[i].BasicInfo.FaultingVa);
                }

            }

            LdrUnlockLoaderLock(0, cookie);
        }

    } while (FALSE);

    if (pWatchInfo) supHeapFree(pWatchInfo);

    return (SkiGetAnomalyCount() == oldAnomalyCount);
}

/*
* SkCheckProcessMemory
*
* Purpose:
*
* Scan process memory for various wubbaboos classic version.
*
*/
BOOL SkCheckProcessMemory(
    _In_ PPROBE_CONTEXT Context
)
{
    UNREFERENCED_PARAMETER(Context);
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    PVOID baseAddress = NULL;
    MEMORY_BASIC_INFORMATION mbi;

    PVOID pvImageBase = NULL;

    while (NT_SUCCESS(NtQueryVirtualMemory(
        NtCurrentProcess(),
        baseAddress,
        MemoryBasicInformation,
        &mbi,
        sizeof(MEMORY_BASIC_INFORMATION),
        NULL)))
    {
        if ((mbi.State != MEM_COMMIT) ||
            (mbi.Protect == PAGE_NOACCESS) ||
            (mbi.Protect & PAGE_GUARD))
        {
            goto Next;
        }

        if ((mbi.Protect & PAGE_EXECUTE) ||
            (mbi.Protect & PAGE_EXECUTE_READ) ||
            (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
            (mbi.Protect & PAGE_EXECUTE_WRITECOPY))
        {
            switch (mbi.Type) {

            case MEM_IMAGE:

                if (!supLdrFindImageByAddress(baseAddress, &pvImageBase)) {
                    SkReportSuspectRegion(&mbi);
                }

                break;

            case MEM_MAPPED:
            case MEM_PRIVATE:
                SkReportSuspectRegion(&mbi);
                break;
            }
        }

    Next:
        baseAddress = RtlOffsetToPointer(baseAddress, mbi.RegionSize);
    }

    return SkiGetAnomalyCount() == oldAnomalyCount;
}
