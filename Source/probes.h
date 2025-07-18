/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023 - 2025
*
*  TITLE:       PROBES.H
*
*  VERSION:     1.00
*
*  DATE:        10 Jul 2025
*
*  Common header file for the program probes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _PROBE_SETTINGS {
    union {
        ULONG Flags;
        struct {
            ULONG CommonChecks : 1;
            ULONG VerifyPEBLdr : 1;
            ULONG VerifyLoadedDrivers : 1;
            ULONG CheckDeviceObjects : 1;
            ULONG VerifyWinVer : 1;
            ULONG ValidateProcList : 1;
            ULONG ValidateThreadList : 1;
            ULONG ValidateNtDllCopies : 1;
            ULONG StackWalk : 1;
            ULONG WsSetWalk : 1;
            ULONG WsSetWatch : 1;
            ULONG HandleTracing : 1;
            ULONG CheckNtOsSyscalls : 1;
            ULONG CheckWin32kSyscalls : 1;
            ULONG CheckDebug : 1;
            ULONG CheckHandles : 1;
            ULONG WalkUserHandleTable : 1;
            ULONG WalkGdiSharedHandleTable : 1;
            ULONG CheckBootConfiguration : 1;
            ULONG CheckProcessMemory : 1;
            ULONG Reserved : 12;
        };
    };
} PROBE_SETTINGS, * PPROBE_SETTINGS;

#define PROBE_FLAGS_COMMON_CHECKS               (0x0001)  
#define PROBE_FLAGS_VERIFY_PEBLDR               (0x0002)  
#define PROBE_FLAGS_VERIFY_LOADED_DRIVERS       (0x0004)  
#define PROBE_FLAGS_CHECK_DEVICE_OBJECTS        (0x0008)  
#define PROBE_FLAGS_VERIFY_WINVER               (0x0010)  
#define PROBE_FLAGS_VALIDATE_PROCLIST           (0x0020)  
#define PROBE_FLAGS_VALIDATE_THREADLIST         (0x0040)  
#define PROBE_FLAGS_VALIDATE_NTDLLCOPIES        (0x0080)  
#define PROBE_FLAGS_STACKWALK                   (0x0100)  
#define PROBE_FLAGS_WSSETWALK                   (0x0200)  
#define PROBE_FLAGS_WSSETWATCH                  (0x0400)  
#define PROBE_FLAGS_HANDLETRACING               (0x0800)  
#define PROBE_FLAGS_CHECK_NTOS_SYSCALLS         (0x1000)  
#define PROBE_FLAGS_CHECK_WIN32K_SYSCALLS       (0x2000) 
#define PROBE_FLAGS_CHECK_DEBUG                 (0x4000)  
#define PROBE_FLAGS_CHECK_HANDLES               (0x8000) 
#define PROBE_FLAGS_WALK_USERHANDLETABLE        (0x10000) 
#define PROBE_FLAGS_WALK_GDISHAREDHANDLETABLE   (0x20000) 
#define PROBE_FLAGS_CHECK_BCD                   (0x40000)
#define PROBE_FLAGS_CHECK_PROCESS_MEMORY        (0x80000)

typedef struct _PROBE_STARTUP_INFO {
    HWND MainWindow;
    PROBE_SETTINGS Settings;
} PROBE_STARTUP_INFO, * PPROBE_STARTUP_INFO;

typedef struct _PROBE_CONTEXT {
    BOOL IsClientElevated;
    BOOL Win10FeaturePack;
    ULONG WindowsMajorVersion;
    ULONG WindowsMinorVersion;
    ULONG ReferenceNtBuildNumber;
    HWND MainWindow;
    PROBE_SETTINGS Settings;
    PVOID NtDllBase;
    PVOID NtOsBase;
    PVOID SelfBase;
    SIZE_T SelfSize;
    CLIENT_ID ClientId;
    ULONG_PTR SystemRangeStart;
    ptrWTGetSignatureInfo WTGetSignatureInfo;
    SYSTEM_BASIC_INFORMATION SystemInfo;
} PROBE_CONTEXT, * PPROBE_CONTEXT;

typedef enum _PS_SCAN_TYPE {
    ScanTypeNative,
    ScanTypeWMI,
    ScanTypeAppCompat
} PS_SCAN_TYPE;

#define SkiInitializeAnomalyCount() {  g_cAnomalies = 0; }
#define SkiIncreaseAnomalyCount() { InterlockedIncrement((PLONG)&g_cAnomalies); }

ULONG SkiGetAnomalyCount();

//
// Reports start.
//
VOID SkReportThreadOpenError(
    _In_ HANDLE WindowHandle,
    _In_ HANDLE ThreadId,
    _In_ BOOL IsClientElevated,
    _In_ NTSTATUS NtStatus);

BOOL SkIsThreadInformationTampered(
    _In_ BOOL SuppressOutput,
    _In_ HANDLE FirstObjectHandle,
    _In_ HANDLE SecondObjectHandle);

VOID SkReportHiddenProcessWindow(
    _In_ HANDLE UniqueProcessId,
    _In_ HANDLE UniqueThreadId,
    _In_ HANDLE WindowHandle);

VOID SkReportGdiObject(
    _In_ HANDLE UniqueProcessId,
    _In_ OBJTYPE ObjectType);

VOID SkReportSuspectHandleEntry(
    _In_ BOOL IsProcess,
    _In_ PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX HandleEntry);

VOID SkReportParentProcessMismatch(
    _In_ ULONG_PTR InheritedFromUniqueProcessId,
    _In_ ULONG_PTR ParentPID);

VOID SkReportExtractionFailureEvent(
    _In_ LPCSTR lpName,
    _In_opt_ LPWSTR lpDescription,
    _In_ LPWSTR lpAnomalyType);

VOID SkReportInvalidHandleClosure(
    _In_ ULONG ConditionType);

VOID SkReportThreadCountRIP();

VOID SkReportSessionIdRIP(
    _In_ ULONG SessionId);

VOID SkReportThreadUnknownRip(
    _In_ ULONG64 Rip);

VOID SkReportInvalidExtractedSSN(
    _In_ LPWSTR lpQueryType);

VOID SkReportUnexpectedSSN(
    _In_ ULONG SsnGot,
    _In_ ULONG SsnExpected);

VOID SkReportNtdllMapRIP(
    _In_ NTDLL_MAP_METHOD Method);

VOID SkReportObTypeListCorruption(
    _In_ ULONG ReportedLength,
    _In_ ULONG ActualLength);

VOID SkReportHandleListCorruption(
    _In_ ULONG ReportedLength,
    _In_ ULONG ActualLength);

VOID SkReportProcListCorruption(
    _In_ ULONG NextEntryOffset,
    _In_ ULONG ExpectedOffset);

VOID SkReportUnknownCode(
    _In_ ULONG_PTR Address,
    _In_ KPROCESSOR_MODE Mode);

VOID SkReportNtCallRIP(
    _In_ NTSTATUS NtStatus,
    _In_ LPWSTR lpMessage,
    _In_opt_ LPWSTR lpApiName,
    _In_opt_ LPWSTR lpQueryName);

VOID SkReportComCallRIP(
    _In_ HRESULT Hresult,
    _In_ LPWSTR lpMessage,
    _In_opt_ LPWSTR lpApiName,
    _In_opt_ LPWSTR lpQueryName);

VOID SkReportWrongWinVersion(
    _In_ LPWSTR lpMessage,
    _In_ ULONG dwVersionMajor,
    _In_ ULONG dwVersionMinor,
    _In_ ULONG dwBuildNumber,
    _In_ LPWSTR lpType);

VOID SkReportVersionResourceBuildNumber(
    _In_ LPCWSTR DllName,
    _In_ ULONG RefBuildNumber,
    _In_ ULONG BuildNumber);

VOID SkReportDebugObjectHandleMismatch(
    _In_ ULONG NumberOfObjects,
    _In_ ULONG NumberOfObjectsThroughQuery);

VOID SkReportDebugObject(
    _In_ ULONG NumberOfObjects,
    _In_ BOOL IsHandlde);

VOID SkReportDeviceObject(
    _In_ LPWSTR DeviceName);

VOID SkReportDriverListModification(
    _In_ ULONG ReportedLength,
    _In_ ULONG ExpectedLength);

VOID SkReportDebugDetected(
    _In_ ULONG Type,
    _In_ LPWSTR RoutineName,
    _In_opt_ LPWSTR InformationClass);

VOID SkReportBcdProbeMismatch(
    _In_ ULONG ApiQueryData,
    _In_ LPWSTR BcdProbeDescription,
    _In_ ULONG BcdProbeValue);

VOID SkReportSuspectRegion(
    _In_ PMEMORY_BASIC_INFORMATION Information);

//
// Reports end.
//

ULONG SkiQueryAndValidateSSN(
    _In_ PROBE_CONTEXT* Context,
    _In_ LPCSTR lpName,
    _In_ PVOID ImageBase,
    _In_ BOOL IsNtDll,
    _In_ BOOL bValidate);

VOID SkStartProbe(
    _In_ PROBE_STARTUP_INFO* Params);

BOOL SkIsCustomKernelSignersPolicyEnabled();
BOOL SkCheckSystemDebugControl();
BOOL SkCheckDebugPrivileges();

BOOL SkCheckBadProcess(
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING ProcessName,
    _In_ PS_SCAN_TYPE ScanType);

BOOL SkVerifyWinVersion(
    _In_ PROBE_CONTEXT* Context);

BOOL SkiSetSyscallIndex(
    _In_ PVOID ImageBase,
    _In_ LPCSTR lpName);

BOOL SkWalkPEB(
    _In_ PPROBE_CONTEXT Context);

BOOL SkWalkLoadedDrivers(
    _In_ PPROBE_CONTEXT Context);

BOOL SkLoadNtDllCopies();

BOOL SkTestSyscalls(
    _In_ PPROBE_CONTEXT Context);

BOOL SkTestVectoredCall(
    _In_ ULONG SystemCallNumber,
    _In_ ULONG_PTR SystemCallAddress,
    _In_ SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX* ReferenceInfo);

BOOL SkWsSetWalk(
    VOID);

BOOL SkWsSetWatch(
    _In_ PPROBE_CONTEXT Context);
BOOL SkStackWalk(
    _In_ PPROBE_CONTEXT Context);

BOOL SkNoKernelWubbaboos();

BOOL SkHandleTracing(
    _In_ PPROBE_CONTEXT Context);

BOOL SkCheckHandles(
    _In_ PROBE_CONTEXT* Context);

BOOL SkCheckDebug(
    _In_ PVOID NtDllBase);

BOOL SkValidateProcessList(
    _In_ PROBE_CONTEXT* Context);

BOOL SkValidateThreadList(
    _In_ PROBE_CONTEXT* Context);

BOOL SkValidateWin32uSyscalls(
    _In_ PROBE_CONTEXT* Context);

BOOL SkUserHandleTableWalk(
    _In_ PROBE_CONTEXT* Context);

BOOL SkGdiSharedHandleTableWalk(
    _In_ PROBE_CONTEXT* Context);

BOOL SkTestBootConfiguration();

BOOL SkCheckProcessMemory(
    _In_ PPROBE_CONTEXT Context);
