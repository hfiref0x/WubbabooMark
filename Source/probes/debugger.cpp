/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023 - 2025
*
*  TITLE:       DEBUGGER.CPP
*
*  VERSION:     1.10
*
*  DATE:        13 Jul 2025
*
*  Debugger detection probes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* SkCheckDebug
*
* Purpose:
*
* Check for debugger presence.
*
*/
BOOL SkCheckDebug(
    _In_ PVOID NtDllBase
)
{
    ULONG oldAnomalyCount = SkiGetAnomalyCount();

    if (supDetectDebug(CheckDrXReg)) {

        SkReportDebugDetected(
            0,
            (LPWSTR)TEXT("Context Registers"),
            DT_DEBUGGER_DRX);
    }

    if (KiSystemCallAddress && SkiSetSyscallIndex(NtDllBase, g_NtTestSet[PROC_INDEX_QIP])) {

        if (supDetectDebug(CheckDebugObjectHandle)) {
            SkReportDebugDetected(0,
                (LPWSTR)TEXT("ProcessDebugObjectHandle"),
                (LPWSTR)(TEXT("NtQueryInformationProcess")));
        }

        if (supDetectDebug(CheckDebugPort)) {
            SkReportDebugDetected(0,
                (LPWSTR)TEXT("ProcessDebugPort"),
                (LPWSTR)(TEXT("NtQueryInformationProcess")));
        }

        if (supDetectDebug(CheckDebugFlags)) {
            SkReportDebugDetected(0,
                (LPWSTR)TEXT("ProcessDebugFlags"),
                (LPWSTR)(TEXT("NtQueryInformationProcess")));
        }
    }

    if (supDetectDebug(CheckUSD)) {
        SkReportDebugDetected(1,
            (LPWSTR)TEXT("USER_SHARED_DATA"),
            NULL);
    }

    return (SkiGetAnomalyCount() == oldAnomalyCount);
}
