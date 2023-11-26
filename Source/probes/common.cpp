/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       COMMON.CPP
*
*  VERSION:     1.00
*
*  DATE:        25 Nov 2023
*
*  Common probes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* SkIsCustomKernelSignersPolicyEnabled
*
* Purpose:
*
* Check for custom kernel signers policy enabled.
*
*/
BOOL SkIsCustomKernelSignersPolicyEnabled()
{
    BOOLEAN bAllowed = FALSE;
    NTSTATUS ntStatus;

    ntStatus = supCICustomKernelSignersAllowed(&bAllowed);
    if (NT_SUCCESS(ntStatus)) {

        if (bAllowed) {

            SkiIncreaseAnomalyCount();
            supReportEvent(evtDetection,
                (LPWSTR)TEXT("Unsafe CI policy is enabled"),
                NULL,
                DT_UNSAFE_CIPOLICY);

            return FALSE;
        }
    }
    else {

        if (ntStatus != STATUS_OBJECT_NAME_NOT_FOUND) {

            SkReportNtCallRIP(ntStatus,
                (LPWSTR)TEXT("Failed to query license data"),
                (LPWSTR)TEXT("CustomKernelSigners"),
                (LPWSTR)TEXT("NtQueryLicenseValue"));

        }
    }

    return TRUE;
}

/*
* SkCheckSystemDebugControl
*
* Purpose:
*
* Check for proper retun of NtSystemDebugControl.
*
*/
BOOL SkCheckSystemDebugControl()
{
    NTSTATUS ntStatus = NtSystemDebugControl(SysDbgQueryModuleInformation,
        NULL, 0, NULL, 0, NULL);

    if (ntStatus == STATUS_DEBUGGER_INACTIVE)
        return TRUE;

    SkiIncreaseAnomalyCount();

    supReportEvent(evtDetection,
        (LPWSTR)TEXT("Kernel Debugger Is Active"),
        (LPWSTR)TEXT("NtSystemDebugControl"),
        DT_KERNELDEBUGGER);

    return FALSE;
}

/*
* SkCheckDebugPrivileges
*
* Purpose:
*
* Check for SeDebugPrivileges, we do not request them.
*
*/
BOOL SkCheckDebugPrivileges()
{
    BOOL bEnabled = FALSE;
    HANDLE tokenHandle = NULL;
    NTSTATUS ntStatus;

    ntStatus = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &tokenHandle);

    if (NT_SUCCESS(ntStatus)) {

        ntStatus = supPrivilegeEnabled(tokenHandle, SE_DEBUG_PRIVILEGE, &bEnabled);
        if (NT_SUCCESS(ntStatus)) {
            if (bEnabled) {
                supReportEvent(evtDetection,
                    (LPWSTR)TEXT("Debug Privileges are enabled for client"),
                    (LPWSTR)TEXT("NtPrivilegeCheck"),
                    DT_PRIVILEGES);

                return FALSE;
            }
        }
        else {
            SkReportNtCallRIP(ntStatus,
                (LPWSTR)TEXT("Failed to check process privileges"),
                (LPWSTR)TEXT("NtPrivilegeCheck"),
                DT_PRIVILEGES);
        }

        NtClose(tokenHandle);
    }
    else {
        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Failed to open process token"),
            (LPWSTR)TEXT("NtOpenProcessToken"),
            DT_PRIVILEGES);
    }

    return TRUE;
}
