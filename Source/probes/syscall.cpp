/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       SYSCALL.CPP
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

BOOL SkiSetSyscallAddress(
    _In_ PVOID ImageBase,
    _In_ LPCSTR lpExtractFrom)
{
    //
    // Extract syscall address.
    //
    KiSystemCallAddress = supSyscallAddressFromServiceEntry(ImageBase, lpExtractFrom);
    if (KiSystemCallAddress == 0) {

        SkiIncreaseAnomalyCount();

        supReportEvent(evtError,
            (LPWSTR)TEXT("Failed to locate system call instruction address"),
            NULL,
            DT_SYSCALL_EXTRACT);

    }

    return (KiSystemCallAddress != 0);
}

BOOL SkpValidatePairOfSSN(
    _In_ ULONG TestSSN,
    _In_ ULONG TestSSN2,
    _In_ LPCSTR lpName,
    _In_ SSN_EXTRACT_METHOD Method
)
{
    WCHAR szText[MAX_TEXT_LENGTH], szName[MAX_TEXT_LENGTH];
    LPWSTR lpMethod;

    BOOL bResult = (TestSSN == TestSSN2);

    if (bResult == FALSE) {

        SkiIncreaseAnomalyCount();

        switch (Method) {

        case SsnSortedScan:
            lpMethod = (LPWSTR)TEXT("Sorting");
            break;
        case SsnRuntimeScan:
            lpMethod = (LPWSTR)TEXT("Runtime");
            break;
        case SsnThreadInformation:
            lpMethod = (LPWSTR)TEXT("Thread Information");
            break;

        default:
            lpMethod = (LPWSTR)TEXT("Instruction");
        }

        StringCchPrintf(szText,
            RTL_NUMBER_OF(szText),
            TEXT("SSN mismatch, got %lu expected %lu (Scan Type: %ws)"), 
            TestSSN, 
            TestSSN2, 
            lpMethod);

        RtlSecureZeroMemory(&szName, sizeof(szName));
        MultiByteToWideChar(CP_ACP, 0, lpName, -1, szName, MAX_TEXT_LENGTH);

        supReportEvent(evtError,
            szText,
            szName,
            DT_SSN_MISMATCH);

    }

    return bResult;
}

BOOL SkiSetSyscallIndex(
    _In_ PVOID ImageBase,
    _In_ LPCSTR lpName)
{
    KiSystemCallNumber = supExtractSSN(SsnSortedScan, ImageBase, TRUE, lpName);
    if (KiSystemCallNumber == INVALID_SYSCALL_ID) {

        SkReportExtractionFailureEvent(lpName,
            NULL,
            DT_SSN_EXTRACTION_DIRECT);

        return FALSE;
    }

    return TRUE;
}

/*
* SkiQueryAndValidateSSN
*
* Purpose:
*
* Extract and validate SSN for given syscall name.
*
*/
ULONG SkiQueryAndValidateSSN(
    _In_ PROBE_CONTEXT *Context,
    _In_ LPCSTR lpName,
    _In_ PVOID ImageBase,
    _In_ BOOL IsNtDll,
    _In_ BOOL bValidate
)
{
    BOOL bW10next = (Context->WindowsMajorVersion >= 10 && Context->ReferenceNtBuildNumber >= NT_WIN11_21H2);
    ULONG testSSN, testSSN2, testSSN3, testSSN4;
    WCHAR szBuffer[MAX_TEXT_LENGTH];

    testSSN2 = INVALID_SYSCALL_ID;
    testSSN3 = INVALID_SYSCALL_ID;
    testSSN4 = INVALID_SYSCALL_ID;

    testSSN = supExtractSSN(SsnInstructionScan, ImageBase, IsNtDll, lpName);
    if (testSSN == INVALID_SYSCALL_ID) {

        szBuffer[0] = 0;

        PBYTE ptrCode;
        ptrCode = (PBYTE)supLdrGetProcAddressEx(ImageBase, lpName);

        if (ptrCode) {
            StringCchPrintf(szBuffer,
                RTL_NUMBER_OF(szBuffer),
                TEXT("Got 0x%02X, 0x%02X, 0x%02X"),
                ptrCode[0], ptrCode[1], ptrCode[2]);
        }

        SkReportExtractionFailureEvent(lpName,
            szBuffer,
            DT_SSN_EXTRACTION_DIRECT);

    }

    if (bValidate) {

        if (!IsNtDll && bW10next) {

            //
            // HACK: Post Win10 win32u fast-failing and address sorting SSN query problem.
            // Since apfnSimpleCall removal MS decided to just fast fail in designated 
            // services instead of removing them. Thus completely ruins the address sorting extraction as 
            // number of fast-failing services are changing between versions and exported routines 
            // ARE NOT syscalls but usermode stubs excluded from SSN adjustment.
            // 
            testSSN2 = testSSN;
        }
        else {

            testSSN2 = supExtractSSN(SsnSortedScan, ImageBase, IsNtDll, lpName);
            if (testSSN2 == INVALID_SYSCALL_ID) {

                SkReportExtractionFailureEvent(lpName,
                    NULL,
                    DT_SSN_EXTRACTION_INDIRECT);

            }

        }

        if (!IsNtDll && bW10next) {

            //
            // HACK: Post Win10 win32u fast-failing and address sorting SSN query problem.
            // While it is all guarded by SEH we cannot use this method also as it will 
            // give as junk stubs ruining SSN adjustments.
            // 
            testSSN3 = testSSN2;
        }
        else {
            testSSN3 = supExtractSSN(SsnRuntimeScan, ImageBase, IsNtDll, lpName);
            if (testSSN3 == INVALID_SYSCALL_ID) {

                SkReportExtractionFailureEvent(lpName,
                    NULL,
                    DT_SSN_EXTRACTION_INDIRECT_RUNTIME);

            }
        }

        testSSN4 = supExtractSSN(SsnThreadInformation, ImageBase, IsNtDll, lpName);
        if (IsNtDll && testSSN4 == INVALID_SYSCALL_ID) {
            SkReportExtractionFailureEvent(lpName,
                NULL,
                DT_SSN_EXTRACTION_THREAD_INFORMATION);
        }

        if (testSSN != INVALID_SYSCALL_ID &&
            testSSN2 != INVALID_SYSCALL_ID &&
            testSSN3 != INVALID_SYSCALL_ID)
        {
            if (SkpValidatePairOfSSN(testSSN, testSSN2, lpName, SsnSortedScan))
                SkpValidatePairOfSSN(testSSN, testSSN3, lpName, SsnRuntimeScan);
        }

        if (IsNtDll && testSSN != INVALID_SYSCALL_ID && testSSN4 != INVALID_SYSCALL_ID) {
            SkpValidatePairOfSSN(testSSN, testSSN4, lpName, SsnThreadInformation);
        }
    }
    return testSSN;
}

/*
* SkpVectoredExceptionHandler
*
* Purpose:
*
* VEH handler for indirect syscall.
*
*/
LONG WINAPI SkpVectoredExceptionHandler(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
    PNTCALL_THREAD_CONTEXT Context;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION &&
        ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)((ULONG64)~((ULONG64)0x1337))) {

        Context = (PNTCALL_THREAD_CONTEXT)RtlGetFrame();
        if (Context) {
            ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
            ExceptionInfo->ContextRecord->Rax = Context->SystemCallNumber;
            ExceptionInfo->ContextRecord->Rip = Context->SystemCallAddress;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_EXECUTE_HANDLER;
}

/*
* SkTestVectoredCall
*
* Purpose:
*
* Execute indirect syscall during VEH.
*
*/
BOOL SkTestVectoredCall(
    _In_ ULONG SystemCallNumber,
    _In_ ULONG_PTR SystemCallAddress,
    _In_ SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX* ReferenceInfo
)
{
    BOOL bCheckPassed = TRUE;
    NTCALL_THREAD_CONTEXT ctx;
    SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX info;
    ULONG returnLength;
    NTSTATUS ntStatus;
    pfnNtQuerySystemInformation Function = (pfnNtQuerySystemInformation)((ULONG64)~((ULONG64)0x1337));

    RtlFillMemory(&ctx, sizeof(ctx), 0);
    ctx.SystemCallAddress = SystemCallAddress;
    ctx.SystemCallNumber = SystemCallNumber;

    if (RtlAddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)&SkpVectoredExceptionHandler)) {

        RtlPushFrame((PTEB_ACTIVE_FRAME)&ctx);

        {
            PUSH_DISABLE_WARNING(6011)
                ntStatus = Function(SystemKernelDebuggerInformationEx, &info, sizeof(info), &returnLength);
            POP_DISABLE_WARNING(6011)
        }

        RtlPopFrame((PTEB_ACTIVE_FRAME)&ctx);

        RtlRemoveVectoredExceptionHandler((PVECTORED_EXCEPTION_HANDLER)&SkpVectoredExceptionHandler);

        if (NT_SUCCESS(ntStatus)) {

            ULONG size = sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX);

            if (size != RtlCompareMemory(ReferenceInfo,
                &info,
                sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)))
            {
                WCHAR szText[MAX_TEXT_LENGTH];

                bCheckPassed = FALSE;

                SkiIncreaseAnomalyCount();

                StringCchPrintf(szText, RTL_NUMBER_OF(szText),
                    TEXT("Modification of the output buffer"));

                supReportEvent(evtDetection,
                    szText,
                    NTQSI_DBG_QUERY,
                    DT_INDIRECT_SYSCALL_VEH);
            }

        }
        else {

            SkReportNtCallRIP(ntStatus,
                (LPWSTR)TEXT("Indirect call failed"),
                (LPWSTR)TEXT("NtQuerySystemInformation"),
                (LPWSTR)TEXT("SystemKernelDebuggerInformationEx"));

        }
    }

    return bCheckPassed;
}

/*
* SkTestSyscalls
*
* Purpose:
*
* Extract SSN's, test calls.
*
*/
BOOL SkTestSyscalls(
    _In_ PPROBE_CONTEXT Context
)
{
    BOOL bSyscallSet = FALSE;
    PVOID imageBase = Context->NtDllBase;
    LPCSTR lpTemplateSyscall;
    NTSTATUS ntStatus, ntStatusNormal;
    ULONG i, oldCount = SkiGetAnomalyCount();
    ULONG length, size;
    WCHAR szText[MAX_TEXT_LENGTH];

    SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX infoBuffer, refInfoBuffer;
    pfnNtQuerySystemInformation pNtQuerySystemInformation;
    PROCESS_BASIC_INFORMATION pbiRef, pbi;
    pfnNtQueryInformationProcess pNtQueryInformationProcess;

    szText[0] = 0;

    //
    // Set syscall instruction address for indirect calls.
    //
    lpTemplateSyscall = g_NtSyscallTemplates[__rdtsc() % RTL_NUMBER_OF(g_NtSyscallTemplates)];
    bSyscallSet = SkiSetSyscallAddress(imageBase, lpTemplateSyscall);

    for (i = 0; i < RTL_NUMBER_OF(g_NtTestSet); i++) {
        
        SkiQueryAndValidateSSN(Context, 
            g_NtTestSet[i], 
            imageBase, 
            TRUE, 
            TRUE);

    }

    //
    // Calls validation.
    //

    size = sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX);
    RtlSecureZeroMemory(&refInfoBuffer, sizeof(refInfoBuffer));

    if (SkiSetSyscallIndex(imageBase, g_NtTestSet[PROC_INDEX_QSI])) {

        //
        // Perform a bait call to be our reference.
        //
        ntStatusNormal = NtQuerySystemInformation(SystemKernelDebuggerInformationEx,
            &refInfoBuffer,
            sizeof(refInfoBuffer),
            &length);

        //
        // Direct calls accessibility.
        //
        RtlSecureZeroMemory(&infoBuffer, sizeof(infoBuffer));
        pNtQuerySystemInformation = (pfnNtQuerySystemInformation)&SkiDirectSystemCall;
        ntStatus = pNtQuerySystemInformation(SystemKernelDebuggerInformationEx,
            &infoBuffer,
            sizeof(infoBuffer),
            &length);

        if (ntStatus != ntStatusNormal) {

            SkiIncreaseAnomalyCount();

            StringCchPrintf(szText, RTL_NUMBER_OF(szText),
                TEXT("Return status mismatch: 0x%lX, expected 0x%lX"),
                ntStatus, ntStatusNormal);

            supReportEvent(evtDetection,
                szText,
                NTQSI_DBG_QUERY,
                DT_DIRECT_SYSCALL);
        }

        if (NT_SUCCESS(ntStatus)) {
            if (size != RtlCompareMemory(
                &refInfoBuffer,
                &infoBuffer,
                sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)))
            {
                SkiIncreaseAnomalyCount();

                StringCchPrintf(szText, RTL_NUMBER_OF(szText),
                    TEXT("Modification of the output buffer"));

                supReportEvent(evtDetection,
                    szText,
                    NTQSI_DBG_QUERY,
                    DT_DIRECT_SYSCALL);
            }
        }

        if (bSyscallSet) {

            //
            // Indirect calls accessibility.
            //
            RtlSecureZeroMemory(&infoBuffer, sizeof(infoBuffer));
            pNtQuerySystemInformation = (pfnNtQuerySystemInformation)&SkiIndirectSystemCall;
            ntStatus = pNtQuerySystemInformation(SystemKernelDebuggerInformationEx,
                &infoBuffer,
                sizeof(infoBuffer),
                &length);

            if (ntStatus != ntStatusNormal) {

                SkiIncreaseAnomalyCount();

                StringCchPrintf(szText, RTL_NUMBER_OF(szText),
                    TEXT("Return status mismatch: 0x%lX, expected 0x%lX"),
                    ntStatus, ntStatusNormal);

                supReportEvent(evtDetection,
                    szText,
                    NTQSI_DBG_QUERY,
                    DT_INDIRECT_SYSCALL);
            }

            if (NT_SUCCESS(ntStatus)) {

                if (size != RtlCompareMemory(&refInfoBuffer,
                    &infoBuffer,
                    sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)))
                {
                    SkiIncreaseAnomalyCount();

                    StringCchPrintf(szText, RTL_NUMBER_OF(szText),
                        TEXT("Modification of the output buffer"));

                    supReportEvent(evtDetection,
                        szText,
                        NTQSI_DBG_QUERY,
                        DT_INDIRECT_SYSCALL);
                }

            }
            else {
                SkiIncreaseAnomalyCount();

                StringCchPrintf(szText, RTL_NUMBER_OF(szText),
                    TEXT("NtQuerySystemInformation failed with NTSTATUS(%lX)"),
                    ntStatus);

                supReportEvent(evtError,
                    szText,
                    NTQSI_DBG_QUERY,
                    DT_INDIRECT_SYSCALL);
            }

            //
            // VEH based indirect call.
            //
#ifndef _DEBUG
            SkTestVectoredCall(KiSystemCallNumber, KiSystemCallAddress, &refInfoBuffer);
#endif
        }

    }

    //
    // Test NtQueryInformationProcess indirect call.
    //
    if (bSyscallSet && SkiSetSyscallIndex(imageBase, g_NtTestSet[PROC_INDEX_QIP])) {

        //
        // Perform a bait call to be our reference.
        //

        ntStatusNormal = NtQueryInformationProcess(NtCurrentProcess(),
            ProcessBasicInformation,
            &pbiRef,
            sizeof(PROCESS_BASIC_INFORMATION),
            &length);

        pNtQueryInformationProcess = (pfnNtQueryInformationProcess)SkiIndirectSystemCall;

        ntStatus = pNtQueryInformationProcess(NtCurrentProcess(),
            ProcessBasicInformation,
            &pbi,
            sizeof(PROCESS_BASIC_INFORMATION),
            &length);

        if (NT_SUCCESS(ntStatus)) {


            if (pbiRef.InheritedFromUniqueProcessId != pbi.InheritedFromUniqueProcessId) {

                SkReportParentProcessMismatch(pbiRef.InheritedFromUniqueProcessId,
                    pbi.InheritedFromUniqueProcessId);

            }

        }
        else {
            SkiIncreaseAnomalyCount();
            StringCchPrintf(szText, RTL_NUMBER_OF(szText),
                TEXT("NtQuerySystemInformation failed with NTSTATUS(%lX)"),
                ntStatus);

            supReportEvent(evtError,
                szText,
                NTQIP_PBI_QUERY,
                DT_INDIRECT_SYSCALL);

        }

    }
    else {
        _strcpy(szText, (LPWSTR)TEXT("Failure of SSN extraction for NtQueryInformationProcess"));

        supReportEvent(evtError,
            szText,
            NTQIP_PBI_QUERY,
            DT_SSN_EXTRACTION_INDIRECT);
    }

    return (SkiGetAnomalyCount() == oldCount);
}

/*
* SkLoadNtDllCopies
*
* Purpose:
*
* Load ntdll copies using different approaches.
*
*/
BOOL SkLoadNtDllCopies()
{
    ULONG i, oldAnomalyCount = SkiGetAnomalyCount();
    NTSTATUS ntStatus;
    PVOID ntdllPointers[MapMethodMax];

    for (i = 0; i < MapMethodMax; i++) {                   
        ntStatus = supMapNtdllCopy((NTDLL_MAP_METHOD)i, &ntdllPointers[i]);
        if (!NT_SUCCESS(ntStatus))
            SkReportNtdllMapRIP((NTDLL_MAP_METHOD)i);
    }

    ULONG testSSN = supExtractSSN(SsnInstructionScan,
        ntdllPointers[UseAbsolutePath],
        TRUE,
        g_NtTestSet[PROC_INDEX_QSI]);

    if (testSSN == INVALID_SYSCALL_ID) {
        SkReportInvalidExtractedSSN((LPWSTR)TEXT("absolute path"));
    }

    ULONG testSSN2 = supExtractSSN(SsnInstructionScan,
        ntdllPointers[UseRelativePath],
        TRUE,
        g_NtTestSet[PROC_INDEX_QSI]);

    if (testSSN2 == INVALID_SYSCALL_ID) {
        SkReportInvalidExtractedSSN((LPWSTR)TEXT("relative path"));
    }

    ULONG testSSN3 = supExtractSSN(SsnInstructionScan,
        ntdllPointers[UseKnownDllsAbsolute],
        TRUE,
        g_NtTestSet[PROC_INDEX_QSI]);

    if (testSSN3 == INVALID_SYSCALL_ID) {
        SkReportInvalidExtractedSSN((LPWSTR)TEXT("KnownDlls (absolute)"));
    }

    ULONG testSSN4 = supExtractSSN(SsnInstructionScan,
        ntdllPointers[UseKnownDllsRelative],
        TRUE,
        g_NtTestSet[PROC_INDEX_QSI]);

    if (testSSN4 == INVALID_SYSCALL_ID) {
        SkReportInvalidExtractedSSN((LPWSTR)TEXT("KnownDlls (relative)"));
    }

    ULONG testSSN5 = supExtractSSN(SsnInstructionScan,
        ntdllPointers[UseLdrKnownDllDirectoryHandle],
        TRUE,
        g_NtTestSet[PROC_INDEX_QSI]);

    if (testSSN5 == INVALID_SYSCALL_ID) {
        SkReportInvalidExtractedSSN((LPWSTR)TEXT("KnownDlls (cached directory handle)"));
    }

    if (testSSN != INVALID_SYSCALL_ID &&
        testSSN2 != INVALID_SYSCALL_ID &&
        testSSN3 != INVALID_SYSCALL_ID &&
        testSSN4 != INVALID_SYSCALL_ID &&
        testSSN5 != INVALID_SYSCALL_ID)
    {
        if (testSSN2 != testSSN) {
            SkReportUnexpectedSSN(testSSN2, testSSN);
        }
        else {
            if (testSSN3 != testSSN2) {
                SkReportUnexpectedSSN(testSSN3, testSSN2);
            }
            else
                if (testSSN4 != testSSN3) {
                    SkReportUnexpectedSSN(testSSN4, testSSN3);
                }
                else if (testSSN5 != testSSN4) {
                    SkReportUnexpectedSSN(testSSN5, testSSN4);
                }
        }
    }

    for (i = 0; i < MapMethodMax; i++) {
        if (ntdllPointers[i]) {
            NtUnmapViewOfSection(NtCurrentProcess(), ntdllPointers[i]);
        }
    }

    return (SkiGetAnomalyCount() == oldAnomalyCount);
}
