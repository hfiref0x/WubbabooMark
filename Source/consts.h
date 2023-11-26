/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       CONSTS.H
*
*  VERSION:     1.00
*
*  DATE:        25 Nov 2023
*
*  Global consts definition file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define NTQSI_DBG_QUERY (LPWSTR)TEXT("SystemKernelDebuggerInformationEx")
#define NTQIP_PBI_QUERY (LPWSTR)TEXT("ProcessBasicInformation")

#define DT_UNSAFE_CIPOLICY (LPWSTR)TEXT("Unsafe CI Policy")

#define DT_DIRECT_SYSCALL (LPWSTR)TEXT("Direct Syscall")
#define DT_INDIRECT_SYSCALL (LPWSTR)TEXT("Indirect Syscall")
#define DT_INDIRECT_SYSCALL_VEH (LPWSTR)TEXT("Indirect Syscall (VEH)")
#define DT_NTDLL_IMAGEBASE_QUERY (LPWSTR)TEXT("ImageBase Query")
#define DT_NTDLL_SOURCE (LPWSTR)TEXT("NTDLL")

#define DT_SSN_MISMATCH (LPWSTR)TEXT("Syscall Mismatch")
#define DT_SSN_EXTRACTION_DIRECT (LPWSTR)TEXT("Direct Extract")
#define DT_SSN_EXTRACTION_INDIRECT (LPWSTR)TEXT("Indirect Extract")
#define DT_SSN_EXTRACTION_INDIRECT_RUNTIME (LPWSTR)TEXT("Indirect Runtime Extract")
#define DT_SSN_EXTRACTION_THREAD_INFORMATION (LPWSTR)TEXT("Thread Information")
#define DT_SSN_EXTRACTION_INVALID_DATA (LPWSTR)TEXT("Invalid Data")
#define DT_PARENT_MISMATCH (LPWSTR)TEXT("Parent Process")
#define DT_BAD_PROCESS_NAME (LPWSTR)TEXT("Blacklisted Name")

#define DT_SYSCALL_EXTRACT (LPWSTR)TEXT("Syscall")
#define DT_INJECTEDCODE (LPWSTR)TEXT("Injected Code")
#define DT_3RDPARTYCODE (LPWSTR)TEXT("3rd-party Code")
#define DT_BUILDNUMBER (LPWSTR)TEXT("Build Number")
#define DT_WINVERSION (LPWSTR)TEXT("Windows Version")
#define DT_SIGNATURE_INVALID (LPWSTR)TEXT("Invalid Signature")
#define DT_SIGNATURE_VERIFY (LPWSTR)TEXT("Signature Verify")
#define DT_WSSET_FAILED (LPWSTR)TEXT("Working Set")
#define DT_SYSINFO_FAILED (LPWSTR)TEXT("System Info")

#define DT_INVALID_SESSIONID (LPWSTR)TEXT("Invalid SessionId")
#define DT_INVALID_THREADCOUNT (LPWSTR)TEXT("Invalid ThreadCount")
#define DT_SUSPICIOUS_THREAD (LPWSTR)TEXT("Suspicious Thread")

#define DT_ERROR_OPEN_OBJECT (LPWSTR)TEXT("Cannot Open")

#define DT_TYPEINFO_MISMATCH (LPWSTR)TEXT("Type Info")
#define DT_KERNELDEBUGGER (LPWSTR)TEXT("Kernel Debugger")
#define DT_PRIVILEGES (LPWSTR)TEXT("Privileges")
#define DT_DATACORRUPTION (LPWSTR)TEXT("Data Corruption")
#define DT_UNKNOWNCODE (LPWSTR)TEXT("Unknown Code")
#define DT_APPCOMPAT (LPWSTR)TEXT("AppCompat")

#define DT_DRIVER_DEVICE (LPWSTR)TEXT("Driver Device")

#define DT_DEBUGGER_TFLAG_RDTSC (LPWSTR)TEXT("TF RDTSC")
#define DT_DEBUGGER_DRX (LPWSTR)TEXT("Debug Registers")

#define DT_WMIQUERY (LPWSTR)TEXT("WMI Query")
#define DT_HIDDENPROCESS (LPWSTR)TEXT("Hidden Process")
#define DT_USEROBJECT (LPWSTR)TEXT("USER Object")
#define DT_GDIOBJECT (LPWSTR)TEXT("GDI Object")

#define DT_BCDMISMATCH (LPWSTR)TEXT("BCD Mismatch")

#define DT_W32INIT_ERROR (LPWSTR)TEXT("Win32 Init Failed")
#define DT_EXCEPTION (LPWSTR)TEXT("Program Exception")
#define DT_UNEXPECTED_BEHAVIOUR (LPWSTR)TEXT("Unexpected behaviour")
#define DT_NTUSER_INTERNAL_ERROR (LPWSTR)TEXT("NTUSER internal information parsing failed")
#define DT_NTGDI_INTERNAL_ERROR (LPWSTR)TEXT("NTGDI internal information parsing failed")

#define T_CSV_FILE_FILTER TEXT("CSV Files\0*.csv\0\0")

#define W32K_TABLE_INDEX_BASE 4096

#define PROC_INDEX_QIP 0
#define PROC_INDEX_QIT 1
#define PROC_INDEX_QSI 2
#define PROC_INDEX_SIT 3
#define PROC_INDEX_SIP 4

static LPCSTR g_NtTestSet[] = {
    "NtQueryInformationProcess",
    "NtQueryInformationThread",
    "NtQuerySystemInformation",
    "NtSetInformationThread",
    "NtSetInformationProcess",
    "NtGetContextThread",
    "NtSetContextThread",
    "NtClose",
    "NtDuplicateObject",
    "NtQueryObject",
    "NtOpenFile",
    "NtCreateSection",
    "NtMapViewOfSection",
    "NtQueryVirtualMemory",
    "NtContinue",
    "NtResumeThread",
    "NtCreateThreadEx",
    "NtQueryPerformanceCounter"
};

static LPCSTR g_NtUserTestSet[] = {
    "NtUserGetForegroundWindow",
    "NtUserQueryWindow",
    "NtUserBuildHwndList",
    "NtUserFindWindowEx",
    "NtUserBlockInput"
};

static LPCSTR g_NtSyscallTemplates[] = {
    "NtAccessCheck",
    "NtAddAtom",
    "NtAlpcCreatePort",
    "NtCreateLowBoxToken",
    "NtCreateResourceManager",
    "NtFilterToken",
    "NtSetEaFile"
};
