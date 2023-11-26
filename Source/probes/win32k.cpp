/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       WIN32K.CPP
*
*  VERSION:     1.00
*
*  DATE:        25 Nov 2023
*
*  NtUser/NtGdi probes (Windows 10 RS4 and above ONLY).
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

BOOL gFirstRun = TRUE;

PSERVERINFO gpsi;
PSHAREDINFO gSharedInfo;
PGDI_SHARED_MEMORY pGdiSharedMemory;

#define SkpWin32RIP()                 \
    supReportEvent(evtError,          \
        DT_NTUSER_INTERNAL_ERROR,     \
        DT_UNEXPECTED_BEHAVIOUR,      \
        DT_W32INIT_ERROR)             \

#define SkpWin32ExceptionRIP(Type)    \
    supReportEvent(evtError,          \
        Type,                         \
        DT_UNEXPECTED_BEHAVIOUR,      \
        DT_EXCEPTION)       

PWND HMValidateHandleNoSecure(
    _In_opt_ HWND hwnd,
    _In_ HANDLE_TYPE bType)
{
    PCLIENTINFO clientInfo = NULL;
    ULONG uniq, dw;
    PWND pobj = NULL;
    HANDLEENTRY* phe;
    PVOID rpdesk;
    DWORD dwError;

    //
    // Get handle index in a handle table.
    //
    dw = HMIndexFromHandle(hwnd);

    //
    // Make sure it is part of handle table.
    //
    if (dw < gpsi->cHandleEntries) {

        phe = &gSharedInfo->aheList[dw];
        uniq = HMUniqFromHandle(hwnd);

        //
        // Check uniq bits against uniq bits in the handle entry.
        //
        if ((uniq == phe->wUniq || uniq == HMUNIQBITS)
            && (!(phe->bFlags & HANDLEF_DESTROY)) // Make sure that the handle is not destroyed.
            && phe->bType == bType)
        {
            //
            // Validate desktop.
            //
            clientInfo = (PCLIENTINFO)NtCurrentTeb()->Win32ClientInfo;
            rpdesk = clientInfo->pDeskInfo->rpdesk;
            if (rpdesk && phe->rpdesk == rpdesk) {

                //
                // Calculate result object adddress.
                //
                pobj = (PWND)RtlOffsetToPointer(phe->hWnd,
                    clientInfo->DesktopHeap);
            }
            //else {               
            //  pobj = NtUserCallOneParam((ULONG_PTR)hwnd, SFI__MAPDESKTOPOBJECT);                              
            //}
        }
    }

    if (pobj) {
        return pobj;
    }

    switch (bType) {

    case TYPE_WINDOW:
        dwError = ERROR_INVALID_WINDOW_HANDLE;
        break;

    case TYPE_MENU:
        dwError = ERROR_INVALID_MENU_HANDLE;
        break;

    case TYPE_CURSOR:
        dwError = ERROR_INVALID_CURSOR_HANDLE;
        break;

    case TYPE_ACCELTABLE:
        dwError = ERROR_INVALID_ACCEL_HANDLE;
        break;

    case TYPE_HOOK:
        dwError = ERROR_INVALID_HOOK_HANDLE;
        break;

    case TYPE_SETWINDOWPOS:
        dwError = ERROR_INVALID_DWP_HANDLE;
        break;

    default:
        dwError = ERROR_INVALID_HANDLE;
        break;
    }

    RtlSetLastWin32Error(dwError);
    return NULL;
}

VOID NtUserTest()
{
    WCHAR szText[MAX_TEXT_LENGTH];

    PWND testWnd = HMValidateHandleNoSecure(GetDesktopWindow(), TYPE_WINDOW);
    if (testWnd) {
        StringCchPrintf(szText,
            RTL_NUMBER_OF(szText),
            TEXT("BEGIN TEST: PWND 0x%llX HWND 0x%llX DesktopHeapOffset 0x%llX\r\n"),
            (ULONG_PTR)testWnd, (ULONG_PTR)testWnd->hWnd, testWnd->DesktopHeapOffset);
    }
    else {
        StringCchPrintf(szText,
            RTL_NUMBER_OF(szText),
            TEXT("FAILURE: HMValidateHandleNoSecure %lu\r\n"), NtCurrentTeb()->LastErrorValue);
    }
    OutputDebugString(szText);
}

BOOL SkiWin32Initialize()
{
    HMODULE hUser32;
    HMODULE hGdi32;

    if (gFirstRun ||
        gSharedInfo == NULL)
    {
        hUser32 = GetModuleHandle(TEXT("user32.dll"));
        if (hUser32 == NULL)
            return FALSE;

        hGdi32 = GetModuleHandle(TEXT("gdi32.dll"));
        if (hGdi32 == NULL)
            return FALSE;

        gSharedInfo = (PSHAREDINFO)GetProcAddress(hUser32, "gSharedInfo");
        if (gSharedInfo == NULL)
            return FALSE;

        gpsi = gSharedInfo->psi;

        pGdiSharedMemory = (PGDI_SHARED_MEMORY)NtCurrentPeb()->GdiSharedHandleTable;

        gFirstRun = FALSE;
    }
    return TRUE;
}

/*
* SkUserHandleTableWalk
*
* Purpose:
*
* Walk UserHandleTable and find windows that doesn't belong to any process that is visible through WINAPI query.
*
*/
BOOL SkUserHandleTableWalk(
    _In_ PROBE_CONTEXT* Context
)
{
    ULONG i, oldAnomalyCount = SkiGetAnomalyCount();
    HANDLEENTRY* phe;
    PVOID processList = NULL;
    PSYSTEM_PROCESS_INFORMATION pEntry;

    __try {

        //
        // Execute any tests only after this call.
        //
        if (!SkiWin32Initialize()) {
            SkpWin32RIP();
            __leave;
        }

        //
        // TESTTESTTESTTESTPLACEHOLDER
        //

        //
        // Prepare process list enumeration.
        //
        processList = supGetSystemInfo(SystemProcessInformation, NULL);
        if (processList == NULL) {

            SkReportNtCallRIP(STATUS_UNSUCCESSFUL,
                (LPWSTR)TEXT("Cannot query process list"),
                (LPWSTR)TEXT("NtQuerySystemInformation"),
                (LPWSTR)TEXT("SystemProcessInformation"));

            __leave;
        }

        //
        // Walk UserHandleTable.
        //
        for (i = 0; i < gpsi->cHandleEntries; i++) {

            phe = &gSharedInfo->aheList[i];

            if (phe->hWnd &&
                (!(phe->bFlags & HANDLEF_DESTROY))
                && phe->bType == TYPE_WINDOW)
            {
                HANDLE threadId = phe->pti;
                HANDLE hWnd = phe->hWnd;

                //
                // Find corresponding entry in process list.
                //
                if (!supThreadToProcessEntry(processList, threadId, &pEntry)) {

                    //
                    // Entry not found, find process id of thread.
                    //
                    HANDLE processId = NULL;
                    NTSTATUS ntStatus = supThreadToProcessHandle(threadId, &processId);
                    if (!NT_SUCCESS(ntStatus)) {
                        //
                        // Could be a synchronization issue or not enough privileges, however report.
                        // Don't raise wubbaboos count as we are not sure what the fuck is this.
                        //
                        SkReportThreadOpenError(hWnd, threadId, Context->IsClientElevated, ntStatus);
                    }
                    else {
                        SkReportHiddenProcessWindow(processId, threadId, hWnd);
                    }

                }
            }
        }

    }
    __finally {

        if (AbnormalTermination()) {
            SkpWin32ExceptionRIP(DT_NTUSER_INTERNAL_ERROR);
            return FALSE;
        }

        if (processList) supHeapFree(processList);
    }


    return (SkiGetAnomalyCount() == oldAnomalyCount);
}

/*
* SkGdiSharedHandleTableWalk
*
* Purpose:
*
* Walk Gdi handle table and find objects that doesn't belong to any process that is visible through WINAPI query.
*
*/
BOOL SkGdiSharedHandleTableWalk(
    _In_ PROBE_CONTEXT* Context)
{
    UNREFERENCED_PARAMETER(Context);

    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    SIZE_T i, cEntries, returnLength;
    PGDI_HANDLE_ENTRY pentry;
    MEMORY_BASIC_INFORMATION mbi;
    PVOID processList = NULL;

    __try {

        //
        // Execute any tests only after this call.
        //
        if (!SkiWin32Initialize()) {
            SkpWin32RIP();
            __leave;
        }

        //
        // Prepare process list enumeration.
        //
        processList = supGetSystemInfo(SystemProcessInformation, NULL);
        if (processList == NULL) {

            SkReportNtCallRIP(STATUS_UNSUCCESSFUL,
                (LPWSTR)TEXT("Cannot query process list"),
                (LPWSTR)TEXT("NtQuerySystemInformation"),
                (LPWSTR)TEXT("SystemProcessInformation"));

            __leave;
        }

        if (NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(),
            pGdiSharedMemory,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &returnLength)))
        {
            //
            // Apprx. number of entries.
            // Warning shared memory contain more data than just handle table.
            //
            cEntries = mbi.RegionSize / sizeof(GDI_HANDLE_ENTRY);
            cEntries = __min(GDI_MAX_HANDLE_COUNT, cEntries);
        }
        else {
            cEntries = GDI_MAX_HANDLE_COUNT;
        }

        for (i = 0; i < cEntries; i++) {

            pentry = &pGdiSharedMemory->aentryHmgr[i];

            ULONG ownerPID = OBJECTOWNER_PID(pentry->ObjectOwner);
            OBJTYPE objType = pentry->Objt;

            //
            // Filter OBJECT_OWNER_*
            //
            if (ownerPID != OBJECT_OWNER_PUBLIC &&
                ownerPID != OBJECT_OWNER_CURRENT &&
                ownerPID != OBJECT_OWNER_NONE &&
                ownerPID != OBJECT_OWNER_ERROR)
            {
                //
                // Check if owner pid is visible to client enumeration.
                //
                if (NULL == supProcessEntryByProcessId(UlongToHandle(ownerPID), processList)) {
                    SkReportGdiObject(UlongToHandle(ownerPID), objType);
                }
            }

        }
    }
    __finally {
        if (AbnormalTermination()) {
            SkpWin32ExceptionRIP(DT_NTGDI_INTERNAL_ERROR);
            return FALSE;
        }
        supHeapFree(processList);
    }

    return (SkiGetAnomalyCount() == oldAnomalyCount);
}

/*
* SkValidateWin32uSyscalls
*
* Purpose:
*
* Verity win32u syscall integrity.
*
*/
BOOL SkValidateWin32uSyscalls(
    _In_ PROBE_CONTEXT* Context)
{
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    PVOID win32uBase = GetModuleHandle(TEXT("win32u.dll"));
    if (win32uBase) {
        for (ULONG i = 0; i < RTL_NUMBER_OF(g_NtUserTestSet); i++)
            SkiQueryAndValidateSSN(Context,
                g_NtUserTestSet[i],
                win32uBase,
                FALSE,
                TRUE);
    }
    return (SkiGetAnomalyCount() == oldAnomalyCount);
}
