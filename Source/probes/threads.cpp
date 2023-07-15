/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       THREADS.CPP
*
*  VERSION:     1.00
*
*  DATE:        01 Jul 2023
*
*  Thread list probes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* SkValidateThreadList
*
* Purpose:
*
* Walk own process thread list and validate thread instruction pointers.
*
*/
BOOL SkValidateThreadList(
    _In_ PROBE_CONTEXT* Context
)
{
    NTSTATUS ntStatus;
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    ULONG nextEntryDelta = 0;
    HANDLE selfPID = Context->ClientId.UniqueProcess, threadObject;

    PVOID processList;
    PSYSTEM_THREAD_INFORMATION threadEntry;

    OBJECT_ATTRIBUTES obja;

    union {
        PSYSTEM_PROCESS_INFORMATION Process;
        PBYTE ListRef;
    } NativeList;

    WCHAR szText[MAX_TEXT_LENGTH];

    InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);

    processList = supGetSystemInfo(SystemProcessInformation, NULL);
    if (processList) {

        NativeList.ListRef = (PBYTE)processList;
        do {

            NativeList.ListRef += nextEntryDelta;

            if (NativeList.Process->UniqueProcessId == selfPID) {
                if (NtCurrentPeb()->SessionId != NativeList.Process->SessionId)
                    SkReportSessionIdRIP(NativeList.Process->SessionId);

                if (NativeList.Process->ThreadCount == 0)
                    SkReportThreadCountRIP();

                for (ULONG i = 0; i < NativeList.Process->ThreadCount; i++) {

                    threadEntry = &NativeList.Process->Threads[i];

                    threadObject = NULL;
                    ntStatus = NtOpenThread(&threadObject,
                        THREAD_GET_CONTEXT,
                        &obja,
                        &threadEntry->ClientId);

                    if (NT_SUCCESS(ntStatus)) {

                        DWORD64 threadRip = 0;
                        PLDR_DATA_TABLE_ENTRY tableEntry;

                        ntStatus = supQueryThreadInstructionPointer(threadObject, &threadRip);
                        if (NT_SUCCESS(ntStatus)) {

                            ntStatus = LdrFindEntryForAddress((PVOID)threadRip, &tableEntry);
                            if (!NT_SUCCESS(ntStatus)) {
                                SkReportThreadUnknownRip(threadRip);
                            }

                        }
                        else {

                            StringCchPrintf(szText, RTL_NUMBER_OF(szText),
                                TEXT("Cannot query RIP of own thread 0x%llX"),
                                (ULONG_PTR)threadEntry->ClientId.UniqueThread);

                            SkReportNtCallRIP(ntStatus,
                                szText,
                                (LPWSTR)TEXT("NtGetContextThread"),
                                (LPWSTR)TEXT("CONTEXT_CONTROL"));

                        }

                        NtClose(threadObject);
                    }
                    else {
                        StringCchPrintf(szText, RTL_NUMBER_OF(szText),
                            TEXT("Cannot open own thread 0x%llX"),
                            (ULONG_PTR)threadEntry->ClientId.UniqueThread);

                        SkReportNtCallRIP(ntStatus,
                            szText,
                            (LPWSTR)TEXT("NtOpenThread"),
                            (LPWSTR)TEXT("THREAD_GET_CONTEXT"));
                    }
                }

                break;
            }

            nextEntryDelta = NativeList.Process->NextEntryDelta;

        } while (nextEntryDelta);

        supHeapFree(processList);
    }
    else {
        SkReportNtCallRIP(STATUS_UNSUCCESSFUL,
            (LPWSTR)TEXT("Cannot query process list"),
            (LPWSTR)TEXT("NtQuerySystemInformation"),
            (LPWSTR)TEXT("SystemProcessInformation"));
    }

    return SkiGetAnomalyCount() == oldAnomalyCount;
}
