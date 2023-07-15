/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       REPORTS.CPP
*
*  VERSION:     1.00
*
*  DATE:        01 Jul 2023
*
*  Probe report workers.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

//
// Failure report policy.
//
// Since this code doesn't use anything that requires advanced privileges (except BootCfg queries)
// and entire class of "tested software" is a far from following any kind of software quality standards 
// -> MOST OF failures here will be traited as detects. Deal with it.
//

VOID SkReportVersionResourceBuildNumber(
    _In_ LPCWSTR DllName,
    _In_ ULONG RefBuildNumber,
    _In_ ULONG BuildNumber
)
{
    WCHAR szBuffer[MAX_TEXT_LENGTH], szText[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    RtlSecureZeroMemory(&szText, sizeof(szText));

    StringCchPrintf(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        TEXT("%lu"),
        RefBuildNumber);

    StringCchPrintf(szText,
        RTL_NUMBER_OF(szText),
        TEXT("Invalid build number in ntdll resources, %ws reports %lu"),
        DllName,
        BuildNumber);


    supReportEvent(evtError,
        szText,
        szBuffer,
        DT_BUILDNUMBER);
}

VOID SkReportWrongWinVersion(
    _In_ LPWSTR lpMessage,
    _In_ ULONG dwVersionMajor,
    _In_ ULONG dwVersionMinor,
    _In_ ULONG dwBuildNumber,
    _In_ LPWSTR lpType
)
{
    WCHAR szText[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    szText[0] = 0;
    ultostr(dwVersionMajor, szText);
    _strcat(szText, TEXT("."));
    ultostr(dwVersionMinor, _strend(szText));
    _strcat(szText, TEXT("."));
    ultostr(dwBuildNumber, _strend(szText));

    supReportEvent(evtError,
        lpMessage,
        szText,
        lpType);
}

VOID SkReportInvalidHandleClosure(
    _In_ ULONG ConditionType
)
{
    WCHAR szText[MAX_TEXT_LENGTH];
    LPWSTR lpCondition;

    if (ConditionType == 0)
        lpCondition = (LPWSTR)TEXT("Handle trace");
    else
        lpCondition = (LPWSTR)TEXT("Unspecified");
    
    StringCchPrintf(szText, RTL_NUMBER_OF(szText),
        TEXT("NtClose anomaly detected, condition: %ws"),
        lpCondition);

    SkiIncreaseAnomalyCount();
    supReportEvent(evtDetection,
        szText,
        (LPWSTR)TEXT("Invalid Handle Closure"),
        DT_INJECTEDCODE);
}

VOID SkReportSuspectRegion(
    _In_ PMEMORY_BASIC_INFORMATION Information
)
{
    WCHAR szText[MAX_TEXT_LENGTH], szDetails[MAX_TEXT_LENGTH];
    WCHAR szValue[20];
    LPWSTR lpType, lpProtect;

    SkiIncreaseAnomalyCount();

    switch (Information->Type) {

    case MEM_MAPPED:
        lpType = (LPWSTR)TEXT("Mapped");
        break;
    case MEM_PRIVATE:
        lpType = (LPWSTR)TEXT("Private");
        break;
    case MEM_IMAGE:
        lpType = (LPWSTR)TEXT("Image");
        break;
    default:
        lpType = (LPWSTR)TEXT("Unknown");
    }

    if (Information->Protect & PAGE_EXECUTE)
        lpProtect = (LPWSTR)TEXT("X");
    else
    if (Information->Protect & PAGE_EXECUTE_READ)
        lpProtect = (LPWSTR)TEXT("RX");
    else
    if (Information->Protect & PAGE_EXECUTE_READWRITE)
        lpProtect = (LPWSTR)TEXT("RWX");
    else
    if (Information->Protect & PAGE_EXECUTE_WRITECOPY)
        lpProtect = (LPWSTR)TEXT("WCX");
    else {
        szValue[0] = L'0';
        szValue[1] = L'x';
        szValue[2] = 0;
        ultohex(Information->Protect, &szValue[2]);
        lpProtect = (LPWSTR)&szValue;
    }

    StringCchPrintf(szText, RTL_NUMBER_OF(szText),
        TEXT("Suspicious region with executable memory, size: 0x%llX, %ws, %ws"),
        Information->RegionSize, lpType, lpProtect);

    StringCchPrintf(szDetails, RTL_NUMBER_OF(szDetails),
        TEXT("0x%llX"),
        (ULONG_PTR)Information->BaseAddress);

    supReportEvent(evtDetection,
        szText,
        szDetails,
        DT_INJECTEDCODE);
}

VOID SkReportNtdllMapRIP(
    _In_ NTDLL_MAP_METHOD Method
)
{
    WCHAR szText[MAX_TEXT_LENGTH];
    LPWSTR lpMethodName = NULL;

    SkiIncreaseAnomalyCount();

    switch (Method) {
    case UseRelativePath:
        lpMethodName = (LPWSTR)TEXT("relative path");
        break;
    case UseKnownDllsAbsolute:
        lpMethodName = (LPWSTR)TEXT("Known Dlls absolute path");
        break;

    case UseKnownDllsRelative:
        lpMethodName = (LPWSTR)TEXT("KnownDlls relative path");
        break;

    case UseLdrKnownDllDirectoryHandle:
        lpMethodName = (LPWSTR)TEXT("KnownDlls cached directory handle");
        break;

    default:
        lpMethodName = (LPWSTR)TEXT("absolute path");
    }

    StringCchPrintf(szText,
        RTL_NUMBER_OF(szText),
        TEXT("Unable to map ntdll copy using %ws"),
        lpMethodName);

    supReportEvent(evtError,
        szText,
        NULL,
        DT_NTDLL_SOURCE);
}

VOID SkReportComCallRIP(
    _In_ HRESULT Hresult,
    _In_ LPWSTR lpMessage,
    _In_opt_ LPWSTR lpApiName,
    _In_opt_ LPWSTR lpQueryName
)
{
    WCHAR szBuffer[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        TEXT("%ws, HRESULT(0x%lX)"),
        lpMessage,
        Hresult);

    supReportEvent(evtError,
        szBuffer,
        lpQueryName,
        lpApiName);
}

VOID SkReportNtCallRIP(
    _In_ NTSTATUS NtStatus,
    _In_ LPWSTR lpMessage,
    _In_opt_ LPWSTR lpApiName,
    _In_opt_ LPWSTR lpQueryName
)
{
    WCHAR szBuffer[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        TEXT("%ws, NTSTATUS(0x%lX)"),
        lpMessage,
        NtStatus);

    supReportEvent(evtError,
        szBuffer,
        lpQueryName,
        lpApiName);
}

VOID SkReportObTypeListCorruption(
    _In_ ULONG ReportedLength,
    _In_ ULONG ActualLength
)
{
    WCHAR szText[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szText, RTL_NUMBER_OF(szText),
        TEXT("Object type list corruption, expected length %lu, got length %lu"),
        ReportedLength, ActualLength);

    supReportEvent(evtDetection,
        szText,
        (LPWSTR)TEXT("ObjectTypesInformation"),
        DT_DATACORRUPTION);

}

VOID SkReportHandleListCorruption(
    _In_ ULONG ReportedLength,
    _In_ ULONG ActualLength
)
{
    WCHAR szText[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szText, RTL_NUMBER_OF(szText),
        TEXT("Handle list corruption, expected length %lu, got length %lu"),
        ReportedLength, ActualLength);

    supReportEvent(evtDetection,
        szText,
        (LPWSTR)TEXT("SystemExtendedHandleInformation"),
        DT_DATACORRUPTION);

}

VOID SkReportProcListCorruption(
    _In_ ULONG NextEntryOffset,
    _In_ ULONG ExpectedOffset
)
{
    WCHAR szText[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szText, RTL_NUMBER_OF(szText),
        TEXT("Process entry corruption, expected offset %lu, got offset %lu"),
        ExpectedOffset, NextEntryOffset);

    supReportEvent(evtDetection,
        szText,
        (LPWSTR)TEXT("SystemProcessInformation"),
        DT_DATACORRUPTION);

}

VOID SkReportThreadUnknownRip(
    _In_ ULONG64 Rip
)
{
    WCHAR szText[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szText,
        RTL_NUMBER_OF(szText),
        TEXT("Thread with RIP outside known modules: 0x%llX"),
        Rip);

    supReportEvent(evtDetection,
        szText,
        NULL,
        DT_SUSPICIOUS_THREAD);
}

VOID SkReportThreadCountRIP()
{
    SkiIncreaseAnomalyCount();

    supReportEvent(evtDetection,
        (LPWSTR)TEXT("System reports invalid thread count for client"),
        NULL,
        DT_INVALID_THREADCOUNT);
}

VOID SkReportSessionIdRIP(
    _In_ ULONG SessionId
)
{
    WCHAR szText[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szText,
        RTL_NUMBER_OF(szText),
        TEXT("PEB: %lu, API: %lu"),
        NtCurrentPeb()->SessionId, SessionId);

    supReportEvent(evtDetection,
        (LPWSTR)TEXT("PEB->SessionId is different of what system reports"),
        szText,
        DT_INVALID_SESSIONID);
}

VOID SkReportInvalidExtractedSSN(
    _In_ LPWSTR lpQueryType
)
{
    WCHAR szBuffer[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        TEXT("Invalid syscall id, ntdll copy mapped using %ws"),
        lpQueryType);

    supReportEvent(evtError,
        szBuffer,
        (LPWSTR)TEXT("0xFFFFFFFFFF"),
        DT_SSN_EXTRACTION_INVALID_DATA);
}

VOID SkReportUnexpectedSSN(
    _In_ ULONG SsnGot,
    _In_ ULONG SsnExpected
)
{
    WCHAR szBuffer[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        TEXT("Syscall index mismatch detected, got 0x%lX, 0x%lX"),
        SsnGot,
        SsnExpected);

    supReportEvent(evtError,
        szBuffer,
        NULL,
        DT_SSN_EXTRACTION_INVALID_DATA);
}

VOID SkReportExtractionFailureEvent(
    _In_ LPCSTR lpName,
    _In_opt_ LPWSTR lpDescription,
    _In_ LPWSTR lpAnomalyType
)
{
    WCHAR szText[MAX_TEXT_LENGTH * 2];
    WCHAR szName[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    RtlSecureZeroMemory(&szName, sizeof(szName));
    MultiByteToWideChar(CP_ACP, 0, lpName, -1, szName, MAX_TEXT_LENGTH);

    StringCchPrintf(szText,
        RTL_NUMBER_OF(szText),
        TEXT("Failure of SSN extraction for %ws"),
        szName);

    supReportEvent(evtError,
        szText,
        lpDescription,
        lpAnomalyType);
}

VOID SkReportParentProcessMismatch(
    _In_ ULONG_PTR InheritedFromUniqueProcessId,
    _In_ ULONG_PTR ParentPID
)
{
    WCHAR szBuffer[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        TEXT("Parent process id mismatch: %llu, expected %llu"),
        InheritedFromUniqueProcessId,
        ParentPID);

    supReportEvent(evtDetection,
        szBuffer,
        NTQIP_PBI_QUERY,
        DT_PARENT_MISMATCH);
}

VOID SkReportSuspectHandleEntry(
    _In_ BOOL IsProcess,
    _In_ PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX HandleEntry
)
{
    WCHAR szBuffer[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();
    StringCchPrintf(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        TEXT("Our %ws handle in %llu with suspicious access rights 0x%lX"),
        IsProcess ? TEXT("process") : TEXT("thread"),
        HandleEntry->UniqueProcessId,
        HandleEntry->GrantedAccess);

    supReportEvent(evtDetection,
        szBuffer,
        (LPWSTR)TEXT("SystemExtendedHandleInformation"),
        (LPWSTR)TEXT("NtQuerySystemInformation"));
}

VOID SkReportDebugObject(
    _In_ ULONG NumberOfObjects,
    _In_ BOOL IsHandlde
)
{
    WCHAR szBuffer[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        (IsHandlde != FALSE) ?
        TEXT("DebugObject type handles are found: %lu") : TEXT("DebugObject type objects are found: %lu"),
        NumberOfObjects);

    supReportEvent(evtDetection,
        szBuffer,
        (LPWSTR)TEXT("SystemExtendedHandleInformation"),
        (LPWSTR)TEXT("NtQuerySystemInformation"));
}

VOID SkReportDebugObjectHandleMismatch(
    _In_ ULONG NumberOfObjects,
    _In_ ULONG NumberOfObjectsThroughQuery
)
{
    WCHAR szBuffer[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();
    StringCchPrintf(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        TEXT("Debug Objects handles mismatch, got %lu, expected %lu"),
        NumberOfObjects,
        NumberOfObjectsThroughQuery);

    supReportEvent(evtDetection,
        szBuffer,
        (LPWSTR)TEXT("ObjectTypesInformation"),
        (LPWSTR)TEXT("NtQueryObject"));
}

VOID SkReportDeviceObject(
    _In_ LPWSTR DeviceName
)
{
    SkiIncreaseAnomalyCount();

    supReportEvent(evtDetection,
        (LPWSTR)TEXT("Suspicious driver device has been detected"),
        DeviceName,
        DT_DRIVER_DEVICE);
}

VOID SkReportDriverListModification(
    _In_ ULONG ReportedLength,
    _In_ ULONG ExpectedLength
)
{
    WCHAR szText[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szText,
        RTL_NUMBER_OF(szText),
        TEXT("Driver list modified, length reported %lu, length expected %lu"),
        ReportedLength,
        ExpectedLength);

    supReportEvent(evtDetection,
        szText,
        (LPWSTR)TEXT("NtQuerySystemInformation"),
        (LPWSTR)TEXT("SystemModuleInformation"));
}

VOID SkReportDebugDetected(
    _In_ ULONG Type,
    _In_ LPWSTR RoutineName,
    _In_opt_ LPWSTR InformationClass
)
{
    SkiIncreaseAnomalyCount();

    supReportEvent(evtDetection,
        (Type == 0) ? (LPWSTR)TEXT("Process Is Under Debug") : (LPWSTR)TEXT("Kernel Debugger Is Active"),
        RoutineName,
        InformationClass);
}

VOID SkReportBcdProbeMismatch(
    _In_ ULONG ApiQueryData,
    _In_ LPWSTR BcdProbeDescription,
    _In_ ULONG BcdProbeValue
)
{
    WCHAR szText[MAX_TEXT_LENGTH];
    WCHAR szDetails[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szText,
        RTL_NUMBER_OF(szText),
        TEXT("Value %ws(%lX) mismatch with data from BCD query"),
        BcdProbeDescription, ApiQueryData);

    StringCchPrintf(szDetails,
        RTL_NUMBER_OF(szDetails),
        TEXT("Element: 0x%lX"),
        BcdProbeValue);

    supReportEvent(evtDetection,
        szText,
        szDetails,
        DT_BCDMISMATCH);
}

VOID SkReportThreadOpenError(
    _In_ HANDLE WindowHandle,
    _In_ HANDLE ThreadId,
    _In_ BOOL IsClientElevated,
    _In_ NTSTATUS NtStatus
)
{
    WCHAR szText[MAX_TEXT_LENGTH];
    WCHAR szStatus[MAX_TEXT_LENGTH];

    StringCchPrintf(szText,
        RTL_NUMBER_OF(szText),
        TEXT("Error opening window %llu owner thread %llu, our client %s elevated"),
        (ULONG_PTR)WindowHandle,
        (ULONG_PTR)ThreadId,
        IsClientElevated ? TEXT("is") : TEXT("is not"));

    StringCchPrintf(szStatus,
        RTL_NUMBER_OF(szStatus),
        TEXT("0x%lX"),
        NtStatus);

    supReportEvent(evtError,
        szText,
        szStatus,
        DT_ERROR_OPEN_OBJECT);
}

VOID SkReportHiddenProcessWindow(
    _In_ HANDLE UniqueProcessId,
    _In_ HANDLE UniqueThreadId,
    _In_ HANDLE WindowHandle
)
{
    WCHAR szText[MAX_TEXT_LENGTH];
    WCHAR szDetails[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szText,
        RTL_NUMBER_OF(szText),
        TEXT("Window belongs to process that is invisible to client"));

    StringCchPrintf(szDetails,
        RTL_NUMBER_OF(szDetails),
        TEXT("PID: %llu, TID: %llu, WND: 0x%llX"),
        (ULONG_PTR)UniqueProcessId, (ULONG_PTR)UniqueThreadId, (ULONG_PTR)WindowHandle);

    supReportEvent(evtDetection,
        szText,
        szDetails,
        DT_USEROBJECT);
}

VOID SkReportGdiObject(
    _In_ HANDLE UniqueProcessId,
    _In_ OBJTYPE ObjectType
)
{
    LPWSTR lpObjectType;
    WCHAR szDetails[MAX_TEXT_LENGTH];
    WCHAR szType[20];

    SkiIncreaseAnomalyCount();

    switch (ObjectType) {
    case DC_TYPE:
        lpObjectType = (LPWSTR)TEXT("DC");
        break;
    case RGN_TYPE:
        lpObjectType = (LPWSTR)TEXT("Region");
        break;
    case PAL_TYPE:
        lpObjectType = (LPWSTR)TEXT("Palette");
        break;
    case SURF_TYPE:
        lpObjectType = (LPWSTR)TEXT("Surface");
        break;
    case LFONT_TYPE:
    case RFONT_TYPE:
        lpObjectType = (LPWSTR)TEXT("Font");
        break;
    case BRUSH_TYPE:
        lpObjectType = (LPWSTR)TEXT("Brush");
        break;
    default:
        szType[0] = L'0';
        szType[1] = L'x';
        szType[2] = 0;
        ultohex(ObjectType, &szType[2]);
        lpObjectType = (LPWSTR)&szType;
        break;
    }

    StringCchPrintf(szDetails,
        RTL_NUMBER_OF(szDetails),
        TEXT("PID: %llu, OBJTYPE: %ws"),
        (ULONG_PTR)UniqueProcessId, lpObjectType);

    supReportEvent(evtDetection,
        (LPWSTR)TEXT("GDI object belongs to process that is invisible to client"),
        szDetails,
        DT_GDIOBJECT);
}

VOID SkReportUnknownCode(
    _In_ ULONG_PTR Address,
    _In_ KPROCESSOR_MODE Mode
)
{ 
    WCHAR szDetails[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szDetails,
        RTL_NUMBER_OF(szDetails),
        TEXT("0x%llX"),
        Address);

    supReportEvent(evtDetection,
        (Mode == 0) ? (LPWSTR)TEXT("Found executable code outside of drivers list") :
        (LPWSTR)TEXT("Found executable code outside of loader list"),
        szDetails,
        DT_UNKNOWNCODE);

}
