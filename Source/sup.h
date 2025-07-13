/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023 - 2025
*
*  TITLE:       SUP.H
*
*  VERSION:     1.10
*
*  DATE:        11 Jul 2025
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define INVALID_SYSCALL_ID (DWORD)MAXDWORD
#define ICON_FIRST IDI_ICON_MAIN
#define ICON_LAST IDI_ICON_CHECK_WARNING

typedef enum _DR_EVENT_TYPE {
    evtInformation = 0,
    evtError,
    evtWarning,
    evtDetection,
    evtCheckPassed
} DR_EVENT_TYPE;

typedef enum _NTDLL_MAP_METHOD {
    UseAbsolutePath = 0,
    UseRelativePath,
    UseKnownDllsAbsolute,
    UseKnownDllsRelative,
    UseLdrKnownDllDirectoryHandle,
    MapMethodMax
} NTDLL_MAP_METHOD;

typedef enum _SSN_EXTRACT_METHOD {
    SsnInstructionScan,
    SsnSortedScan,
    SsnRuntimeScan,
    SsnThreadInformation
} SSN_EXTRACT_METHOD;

typedef enum _DBG_CHECK_METHOD {
    CheckDrXReg,
    CheckDebugObjectHandle,
    CheckDebugPort,
    CheckDebugFlags,
    CheckUSD
} DBG_CHECK_METHOD;

typedef VOID(NTAPI* PFEFN)();

//
// Ripped from vmprotect with brave and courage.
//

typedef enum _KNOWN_BUILD_NUMBER {
    WINDOWS_7 = 7600,
    WINDOWS_7_SP1 = 7601,
    WINDOWS_8 = 9200,
    WINDOWS_8_1 = 9600,
    WINDOWS_10_TH1 = 10240,
    WINDOWS_10_TH2 = 10586,
    WINDOWS_10_RS1 = 14393,
    WINDOWS_10_RS2 = 15063,
    WINDOWS_10_RS3 = 16299,
    WINDOWS_10_RS4 = 17134,
    WINDOWS_10_RS5 = 17763,
    WINDOWS_10_19H1 = 18362,
    WINDOWS_10_19H2 = 18363,
    WINDOWS_10_20H1 = 19041,
    WINDOWS_10_20H2 = 19042,
    WINDOWS_10_21H1 = 19043,
    WINDOWS_10_21H2 = 19044,
    WINDOWS_10_22H2 = 19045,
    WINDOWS_11_21H2 = 22000,
    WINDOWS_11_22H2 = 22621
} KNOWN_BUILD_NUMBER;

#define IS_KNOWN_WINDOWS_BUILD(b) ( \
                                    (b) == WINDOWS_7 || \
                                    (b) == WINDOWS_7_SP1 || \
                                    (b) == WINDOWS_8 || \
                                    (b) == WINDOWS_8_1 || \
                                    (b) == WINDOWS_10_TH1 || \
                                    (b) == WINDOWS_10_TH2 || \
                                    (b) == WINDOWS_10_RS1 || \
                                    (b) == WINDOWS_10_RS2 || \
                                    (b) == WINDOWS_10_RS3 || \
                                    (b) == WINDOWS_10_RS4 || \
                                    (b) == WINDOWS_10_RS5 || \
                                    (b) == WINDOWS_10_19H1 || \
                                    (b) == WINDOWS_10_19H2 || \
                                    (b) == WINDOWS_10_20H1 || \
                                    (b) == WINDOWS_10_20H2 || \
                                    (b) == WINDOWS_10_21H1 || \
                                    (b) == WINDOWS_10_21H2 || \
                                    (b) == WINDOWS_10_22H2 \
                                  )

//
// End of rip.
//

#define IS_WIN10_FEATURE_PACK_RANGE(b) ((b) >= WINDOWS_10_20H1 && (b) <= WINDOWS_10_22H2) //fake versions (all based on 19041)

typedef enum _SIGNATURE_INFO_TYPE {
    SIT_UNKNOWN = 0x0,
    SIT_AUTHENTICODE = 0x1,
    SIT_CATALOG = 0x2
} SIGNATURE_INFO_TYPE;

#define SIF_AUTHENTICODE_SIGNED 0x1
#define SIF_CATALOG_SIGNED      0x2
#define SIF_VERSION_INFO        0x4
#define SIF_CHECK_OS_BINARY     0x800
#define SIF_BASE_VERIFICATION   0x1000
#define SIF_CATALOG_FIRST       0x2000
#define SIF_MOTW                0x4000

typedef enum _SIGNATURE_STATE {
    SIGNATURE_STATE_UNSIGNED_MISSING = 0x0,
    SIGNATURE_STATE_UNSIGNED_UNSUPPORTED = 0x1,
    SIGNATURE_STATE_UNSIGNED_POLICY = 0x2,
    SIGNATURE_STATE_INVALID_CORRUPT = 0x3,
    SIGNATURE_STATE_INVALID_POLICY = 0x4,
    SIGNATURE_STATE_VALID = 0x5,
    SIGNATURE_STATE_TRUSTED = 0x6,
    SIGNATURE_STATE_UNTRUSTED = 0x7,
} SIGNATURE_STATE;

typedef enum _SIGNATURE_INFO_AVAILABILITY {
    SIA_DISPLAYNAME = 1,
    SIA_PUBLISHERNAME = 2,
    SIA_MOREINFOURL = 4,
    SIA_HASH = 8,
    SIA_PRODUCTVERSION = 16
} SIGNATURE_INFO_AVAILABILITY;

typedef struct _SIGNATURE_INFO {
    DWORD cbSize;
    SIGNATURE_STATE SignatureState;
    SIGNATURE_INFO_TYPE SignatureType;
    DWORD dwSignatureInfoAvailability;
    DWORD dwInfoAvailability;
    PWSTR pszDisplayName;
    DWORD cchDisplayName;
    PWSTR pszPublisherName;
    DWORD cchPublisherName;
    PWSTR pszMoreInfoURL;
    DWORD cchMoreInfoURL;
    LPBYTE prgbHash;
    DWORD cbHash;
    BOOL fOSBinary; //True if the item is signed as part of an operating system release
} SIGNATURE_INFO, * PSIGNATURE_INFO;

typedef LONG(WINAPI* ptrWTGetSignatureInfo)(
    LPWSTR pszFile,
    HANDLE hFile,
    ULONG sigInfoFlags, //SIF_*
    SIGNATURE_INFO* siginfo,
    VOID* ppCertContext,
    VOID* phWVTStateData
    );

typedef struct _SUP_THREAD_INFO {
    PVOID StartAddress;
    PVOID Win32StartAddress;
} SUP_THREAD_INFO, * PSUP_THREAD_INFO;

typedef struct _LVCOLUMNS_DATA {
    LPWSTR Name;
    INT Width;
    INT Format;
    INT ImageIndex;
} LVCOLUMNS_DATA, * PLVCOLUMNS_DATA;

typedef struct _EXPORT_NODE {
    CHAR Name[256];
    ULONG_PTR Address;
    struct _EXPORT_NODE* Next;
} EXPORT_NODE, * PEXPORT_NODE;

typedef struct _NTCALL_THREAD_CONTEXT {
    TEB_ACTIVE_FRAME Frame;
    ULONG SystemCallNumber;
    ULONG_PTR SystemCallAddress;
} NTCALL_THREAD_CONTEXT, * PNTCALL_THREAD_CONTEXT;

typedef struct _OBJSCANPARAM {
    PCWSTR Buffer;
    ULONG BufferSize;
} OBJSCANPARAM, * POBJSCANPARAM;

#define NTSTUB_ROUTINE(n) NTSTATUS NTAPI n()

typedef NTSTATUS(NTAPI* PNTSTUBFN)();

typedef struct _SUP_NTSTUB {
    LPCSTR Name;
    PNTSTUBFN Stub;
} SUP_NTSTUB, * PSUB_NTSTUB;

typedef NTSTATUS(NTAPI* PENUMOBJECTSCALLBACK)(
    _In_ POBJECT_DIRECTORY_INFORMATION Entry,
    _In_opt_ PVOID CallbackParam);

#define NTQSI_MAX_BUFFER_LENGTH (512 * 1024 * 1024)
#define NTQOI_MAX_BUFER_LENGTH (128 * 1024 * 1024)

#define supHeapAlloc(Size) RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size)
#define supHeapFree(BaseAddress) RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, BaseAddress);

VOID supRunAsAdmin(
    VOID);

BOOL supWriteConfiguration(
    _In_ struct _PROBE_SETTINGS *Settings);

BOOL supReadConfiguration(
    _Out_ struct _PROBE_SETTINGS *Settings);

VOID supSetMitigationPolicies();

VOID supStatusBarSetText(
    _In_ HWND StatusBar,
    _In_ WPARAM Index,
    _In_ LPCWSTR Text);

VOID supReportEventEx(
    _In_ DR_EVENT_TYPE EventType,
    _In_ LPWSTR lpEvent,
    _In_opt_ LPWSTR lpDescription,
    _In_opt_ LPWSTR lpAnomalyType,
    _In_ ULONG_PTR lParam,
    _In_ BOOLEAN fCheckDuplicate);

VOID supReportEvent(
    _In_ DR_EVENT_TYPE EventType,
    _In_ LPWSTR lpEvent,
    _In_opt_ LPWSTR lpDescription,
    _In_opt_ LPWSTR lpAnomalyType);

VOID supShowWelcomeBanner();
BOOL supInitializeSecurityForCOM();

#define REPORT_TEST_PASSED(TestType) supReportEvent(evtInformation, (LPWSTR)TestType, (LPWSTR)TEXT("PASSED"), NULL)
#define REPORT_TEST_SKIPPED(Text) supReportEvent(evtWarning, (LPWSTR)Text, (LPWSTR)TEXT("SKIPPED"), NULL)
#define REPORT_RIP(RipText) supReportEvent(evtError, (LPWSTR)RipText, (LPWSTR)TEXT("FAILURE"), NULL)

ULONG NTAPI supUnhandledExceptionFilter(
    _In_ PEXCEPTION_POINTERS ExceptionInfo);

HANDLE supGetCurrentProcessToken(
    VOID);
BOOL supUserIsFullAdmin(
    VOID);

SIZE_T supFindUnicodeStringSubString(
    _In_ PUNICODE_STRING String,
    _In_ PUNICODE_STRING SubString);

BOOL supListViewExportToFile(
    _In_ LPCWSTR FileName,
    _In_ HWND WindowHandle,
    _In_ HWND ListView);

BOOL supConvertFileName(
    _In_ LPWSTR NtFileName,
    _Inout_ LPWSTR DosFileName,
    _In_ SIZE_T ccDosFileName);

NTSTATUS supConvertToUnicode(
    _In_ LPCSTR AnsiString,
    _Inout_ PUNICODE_STRING UnicodeString);

NTSTATUS supGetObjectTypesInfo(
    _Out_ PULONG ReturnLength,
    _Out_ PVOID* Buffer);

NTSTATUS supGetWin32FileName(
    _In_ LPCWSTR NtFileName,
    _Out_ LPWSTR* Win32FileName);

NTSTATUS supInitializeKnownSids();
VOID supCacheKnownDllsEntries();

PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength);

PVOID supGetProcessInfoVariableSize(
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_opt_ PULONG ReturnLength);

PVOID supVirtualAlloc(
    _In_ SIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect);

BOOL supVirtualFree(
    _In_ PVOID Memory);

NTSTATUS supMapImageNoExecute(
    _In_ PUNICODE_STRING ImagePath,
    _Out_ PVOID* BaseAddress);

NTSTATUS supIsFileOwnedByTrustedInstallerSystemOrAdmins(
    _In_ KPROCESSOR_MODE Mode,
    _In_ HANDLE hFile,
    _In_ PUNICODE_STRING pusName);

NTSTATUS supPrivilegeEnabled(
    _In_ HANDLE ClientToken,
    _In_ ULONG Privilege,
    _Out_ LPBOOL pfResult);

NTSTATUS supQueryNtOsInformation(
    _Out_ PULONG BuildNumber,
    _Out_opt_ PVOID* MappedNtOs);

NTSTATUS supGetConsoleHostForSelf(
    _Out_ PHANDLE ConsoleHostId);

NTSTATUS supEmptyWorkingSet();

HIMAGELIST supLoadImageList(
    _In_ HINSTANCE hInstance);

VOID supSetListViewSettings(
    _In_ HWND hwndLV,
    _In_ DWORD dwExtendedStyle,
    _In_ BOOL fSetTheme,
    _In_opt_ HIMAGELIST hImageList,
    _In_ INT iImageList);

ULONG supAddLVColumnsFromArray(
    _In_ HWND ListView,
    _In_ PLVCOLUMNS_DATA ColumnsData,
    _In_ ULONG NumberOfColumns);

INT supAddListViewColumn(
    _In_ HWND ListViewHwnd,
    _In_ INT ColumnIndex,
    _In_ INT SubItemIndex,
    _In_ INT OrderIndex,
    _In_ INT Format,
    _In_ LPWSTR Text,
    _In_ INT Width);

HRESULT supShellExecInExplorerProcess(
    _In_ PCWSTR pszFile,
    _In_opt_ PCWSTR pszArguments);

ULONG supExtractSSN(
    _In_ SSN_EXTRACT_METHOD Method,
    _In_ PVOID ImageBase,
    _In_ BOOL IsNtDll,
    _In_ LPCSTR FunctionName);

LPVOID supLdrGetProcAddressEx(
    _In_ LPVOID ImageBase,
    _In_ LPCSTR RoutineName);

PVOID supLdrFindImageByAddress(
    _In_opt_ PVOID AddressValue,
    _Out_ PVOID* ImageBase);

PVOID supLdrFindImageByAddressEx(
    _In_ BOOL LockLoader,
    _In_opt_ PVOID AddressValue,
    _Out_ PVOID* ImageBase);

PVOID supGetImageBaseUnsafe(
    _In_ ULONG_PTR AddressValue);

ULONG supEnumServiceExports(
    _In_ HANDLE HeapHandle,
    _In_ LPVOID ImageBase,
    _In_ BOOL IsNtDll,
    _Out_ EXPORT_NODE** ExportTable);

ULONG_PTR supSyscallAddressFromServiceEntry(
    _In_ PVOID ImageBase,
    _In_ LPCSTR FunctionName);

NTSTATUS supVerifyFileSignature(
    _In_ KPROCESSOR_MODE Mode,
    _In_ LPWSTR lpFileName,
    _In_ BOOL OsBinaryCheck,
    _In_ ptrWTGetSignatureInfo pWTGetSignatureInfo);

NTSTATUS supQueryThreadStartAddress(
    _In_ HANDLE ThreadHandle,
    _Out_ SUP_THREAD_INFO* ThreadInformation);

NTSTATUS supQueryThreadInstructionPointer(
    _In_ HANDLE Threadhandle,
    _Out_ PDWORD64 InstructionPointer);

ULONG supParseOSBuildBumber(
    _In_ PVOID ImageBase);

NTSTATUS supMapNtdllCopy(
    _In_ NTDLL_MAP_METHOD MapMethod,
    _Out_ PVOID* BaseAddress);

BOOLEAN supDetectDebug(
    _In_ DBG_CHECK_METHOD Method);

PVOID supGetLoadedModulesList(
    _In_ BOOL ExtendedOutput,
    _Out_opt_ PULONG ReturnLength);

BOOLEAN supIsObjectExists(
    _In_ LPCWSTR RootDirectory,
    _In_ LPCWSTR ObjectName);

BOOL supFindModuleEntryByAddress(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ PVOID Address,
    _Out_ PULONG ModuleIndex);

NTSTATUS supGetMappedFileName(
    _In_ PVOID lpAddress,
    _Out_ POBJECT_NAME_INFORMATION* ObjectNameInformation);

NTSTATUS supQueryImageInformation(
    _In_ PVOID Address,
    _Out_ PVOID* ImageBase,
    _Out_ PSIZE_T SizeOfImage);

ULONG supExtractSyscallNumberFromRoutine(
    _In_ PFEFN Routine);

PVOID supGetNtStubByName(
    _In_ LPCSTR lpName);

PVOID supProcessEntryByProcessId(
    _In_ HANDLE UniqueProcessId,
    _In_ PVOID ProcessList);

BOOL supThreadToProcessEntry(
    _In_ PVOID ProcessList,
    _In_ HANDLE ThreadId,
    _Out_ PSYSTEM_PROCESS_INFORMATION* ProcessListEntry);

NTSTATUS supThreadToProcessHandle(
    _In_ HANDLE ThreadId,
    _Out_ PHANDLE ProcessId);

NTSTATUS supIsProcessElevated(
    _In_ HANDLE ProcessId,
    _Out_ PBOOL Elevated);

NTSTATUS supCICustomKernelSignersAllowed(
    _Out_ PBOOLEAN bAllowed);

ULONG_PTR supQuerySystemRangeStart(
    VOID);
