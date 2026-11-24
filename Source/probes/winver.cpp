/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023 - 2026
*
*  TITLE:       WINVER.CPP
*
*  VERSION:     1.50
*
*  DATE:        23 Nov 2026
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* SkpValidateVersionDataWMI
*
* Purpose:
*
* Query windows version numbers by WMI call for CIMWin32.
*
*/
HRESULT SkpValidateVersionDataWMI(
    _In_ ULONG TestMajorVersion,
    _In_ ULONG TestMinorVersion,
    _In_ ULONG TestBuildNumber,
    _Out_ PBOOL ValidateResult
)
{
    BOOL bSeemsLegit = FALSE;
    HRESULT hr = S_OK, hrFunc = S_OK;
    IWbemLocator* WbemLocator = NULL;
    IWbemServices* WbemServices = NULL;
    IEnumWbemClassObject* enumWbem = NULL;
    IWbemClassObject* result = NULL;
    BSTR bstrServer = NULL;
    BSTR bstrQuery = NULL, bstrQueryLanguage = NULL;

    ULONG returnedCount = 0;

    do {
        bstrServer = SysAllocString(L"ROOT\\CIMV2"); //CIMWin32
        bstrQuery = SysAllocString(L"SELECT * FROM Win32_OperatingSystem");
        bstrQueryLanguage = SysAllocString(L"WQL");

        if ((bstrServer == NULL) ||
            (bstrQuery == NULL) ||
            (bstrQueryLanguage == NULL))
        {
            hrFunc = E_FAIL;
            SkReportComCallRIP(E_FAIL,
                (LPWSTR)TEXT("Cannot allocate memory for string"),
                (LPWSTR)__FUNCTIONW__,
                NULL);
            break;
        }

        hr = CoCreateInstance(CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID*)&WbemLocator);

        if (FAILED(hr)) {
            hrFunc = hr;
            SkReportComCallRIP(hr,
                (LPWSTR)TEXT("Cannot create locator instance"),
                (LPWSTR)__FUNCTIONW__,
                NULL);
            break;
        }

        hr = WbemLocator->ConnectServer(bstrServer, NULL, NULL, NULL, 0, NULL, NULL, &WbemServices);
        if (FAILED(hr)) {
            hrFunc = hr;
            SkReportComCallRIP(hr,
                (LPWSTR)TEXT("Cannot connect CIMV2 server"),
                (LPWSTR)__FUNCTIONW__,
                NULL);
            break;
        }

        hr = WbemServices->ExecQuery(bstrQueryLanguage,
            bstrQuery,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &enumWbem);
        if (FAILED(hr)) {
            hrFunc = hr;
            SkReportComCallRIP(hr,
                (LPWSTR)TEXT("Failed to execute query"),
                (LPWSTR)__FUNCTIONW__,
                NULL);
            break;
        }

        VARIANT vtBuildNumber;
        VARIANT vtVersion;

        VariantInit(&vtBuildNumber);
        VariantInit(&vtVersion);

        while ((hr = enumWbem->Next(WBEM_INFINITE, 1, &result, &returnedCount)) == S_OK) {

            HRESULT hr2, hr3;

            hr2 = result->Get(L"BuildNumber", 0, &vtBuildNumber, 0, 0);

            if (SUCCEEDED(hr2)) {
                hr2 = VariantChangeType(&vtBuildNumber, &vtBuildNumber, 0, VT_UI4);
                if (SUCCEEDED(hr2))
                    bSeemsLegit = (vtBuildNumber.uintVal == TestBuildNumber);
            }

            //
            // Build seems same, compare full version string.
            //
            if (bSeemsLegit) {

                hr3 = result->Get(L"Version", 0, &vtVersion, 0, 0);
                if (SUCCEEDED(hr3) && vtVersion.vt == VT_BSTR) {

                    WCHAR szVersion[20];
                    StringCchPrintf(szVersion, _countof(szVersion),
                        TEXT("%lu.%lu.%lu"),
                        TestMajorVersion,
                        TestMinorVersion,
                        TestBuildNumber);

                    bSeemsLegit = (_strcmpi(szVersion, vtVersion.bstrVal) == 0);

                }
                else {
                    bSeemsLegit = FALSE; //unexpected failure
                    hrFunc = E_FAIL;
                    SkReportComCallRIP(hr3,
                        (LPWSTR)TEXT("Failed to get data"),
                        (LPWSTR)__FUNCTIONW__,
                        NULL);
                }

            }

            VariantClear(&vtBuildNumber);
            VariantClear(&vtVersion);
            result->Release();
        }

    } while (FALSE);

    if (enumWbem) enumWbem->Release();
    if (WbemServices) WbemServices->Release();
    if (WbemLocator) WbemLocator->Release();

    if (bstrServer) SysFreeString(bstrServer);
    if (bstrQueryLanguage) SysFreeString(bstrQueryLanguage);
    if (bstrQuery) SysFreeString(bstrQuery);

    *ValidateResult = bSeemsLegit;

    return hrFunc;
}

/*
* SkpValidateSyscallLayoutForVersionData
*
* Purpose:
*
* Find discrepancy between Windows version build and syscall layout.
*
*/
PVOID SkpValidateSyscallLayoutForVersionData(
    _In_ HMODULE NtDllBase,
    _In_ ULONG TestBuildNumber
)
{
    LPCSTR lpName = NULL;

    //
    // MSFT verified.
    //
    do {

        if (TestBuildNumber >= NT_WIN7_RTM && TestBuildNumber <= NT_WIN7_SP1) {
            lpName = (LPCSTR)"NtGetPlugPlayEvent";
            break;
        }

        if (TestBuildNumber == NT_WIN8_RTM) {
            lpName = (LPCSTR)"NtCreateIRTimer";
            break;
        }

        if (TestBuildNumber == NT_WIN8_BLUE) {
            lpName = (LPCSTR)"NtCancelTimer2";
            break;
        }

        switch (TestBuildNumber) {

        case NT_WIN10_THRESHOLD1:
            lpName = (LPCSTR)"NtSetInformationSymbolicLink";
            break;

        case NT_WIN10_THRESHOLD2:
            lpName = (LPCSTR)"NtCreateEnclave";
            break;

        case NT_WIN10_REDSTONE1:
            lpName = (LPCSTR)"NtOpenRegistryTransaction";
            break;

        case NT_WIN10_REDSTONE2:
            lpName = (LPCSTR)"NtCompareSigningLevels";
            break;

        case NT_WIN10_REDSTONE3:
            lpName = (LPCSTR)"NtNotifyChangeDirectoryFileEx";
            break;

        case NT_WIN10_REDSTONE4:
            lpName = (LPCSTR)"NtAllocateVirtualMemoryEx";
            break;

        case NT_WIN10_REDSTONE5:
            lpName = (LPCSTR)"NtCreateSectionEx";
            break;

        case NT_WIN10_19H1:
        case NT_WIN10_19H2: //feature pack
            lpName = (LPCSTR)"NtCreateCrossVmEvent";
            break;
        default:
            break;
        }

        if (lpName)
            break;

        if (TestBuildNumber >= NT_WIN10_20H1 && TestBuildNumber <= NT_WIN10_22H2) {
            lpName = (LPCSTR)"NtPssCaptureVaSpaceBulk";
            break;
        }

        if (TestBuildNumber == NT_WINSRV_21H1) {
            lpName = (LPCSTR)"NtReadVirtualMemoryEx";
            break;
        }

        if (TestBuildNumber == NT_WIN11_21H2) {
            lpName = (LPCSTR)"NtCreateIoRing";
            break;
        }

        if (TestBuildNumber == NT_WIN11_22H2 || TestBuildNumber == NT_WIN11_23H2) {
            lpName = (LPCSTR)"NtCreateCpuPartition";
            break;
        }

        if (TestBuildNumber >= NT_WIN11_24H2 && TestBuildNumber <= NT_WIN11_26H2) {
            lpName = (LPCSTR)"NtAlertThreadByThreadIdEx";
            break;
        }

        //
        // This one could be missing in early win11 previews and dev builds as it was introduced later.
        // It doesn't matter, if you want to play this hard, okay.
        //
        if (TestBuildNumber > NT_WIN11_26H2) {
            lpName = (LPCSTR)"NtManageWobTicket";
            break;
        }

        lpName = NULL;

    } while (FALSE);

    if (lpName == NULL)
        return NULL;

    return (PVOID)GetProcAddress(NtDllBase, lpName);
}

/*
* SkpIsBuildAcceptableForVersion
*
* Purpose:
*
* Check that the build number is valid for the reported major/minor version.
* SKU (client/server) association is a separate concern, handled elsewhere.
*
*/
static BOOL SkpIsBuildAcceptableForVersion(
    _In_ ULONG MajorVersion,
    _In_ ULONG MinorVersion,
    _In_ ULONG BuildNumber
)
{
    switch (MajorVersion) {
    case 6:
        switch (MinorVersion) {
        case 1: // Windows 7
            return (BuildNumber == NT_WIN7_RTM || BuildNumber == NT_WIN7_SP1);
        case 2: // Windows 8
            return (BuildNumber == NT_WIN8_RTM);
        case 3: // Windows 8.1
            return (BuildNumber == NT_WIN8_BLUE);
        default: // 6.0 (Vista) unsupported, 6.4 pre-release
            return FALSE;
        }
    case 10:
        if (MinorVersion != 0) return FALSE; // 10.x always reports 10.0
        return (BuildNumber >= NT_WIN10_THRESHOLD1 &&
            IS_KNOWN_WINDOWS_BUILD(BuildNumber));
    default:
        return FALSE;
    }
}

//
// SkpExpectedKernelBaseBuild
// 
// Purpose: 
// 
// Map a reported build to its expected kernel base.
// The kernel's compiled NtBuildNumber is the family BASE build, never an
// enablement "fake" build.
//
ULONG SkpExpectedKernelBaseBuild(
    _In_ ULONG ReportedBuild
)
{
    if (IS_WIN10_19H_FEATURE_PACK_RANGE(ReportedBuild))
        return NT_WIN10_19H1;  // 18362
    if (IS_WIN10_FEATURE_PACK_RANGE(ReportedBuild))
        return NT_WIN10_20H1;  // 19041
    if (IS_WIN11_NI_FEATURE_PACK_RANGE(ReportedBuild))
        return NT_WIN11_22H2;  // 22621
    if (IS_WIN11_GE_FEATURE_PACK_RANGE(ReportedBuild))
        return NT_WIN11_24H2;  // 26100

    return ReportedBuild; // real (non-eKB) build is its own base
}

/*
* SkVerifyWinVersion
*
* Purpose:
*
* Query windows version numbers and verify them to be somewhat valid.
*
*/
BOOL SkVerifyWinVersion(
    _In_ PROBE_CONTEXT* Context
)
{
    struct {
        LPCWSTR DllName;
        ULONG VersionBuildNumber;
    } DllData[] = {
        { L"ntdll.dll", 0 },        //
        { L"kernel32.dll", 0 },     // Only KnownDlls 
        { L"kernelbase.dll", 0 },   //
        { L"user32.dll", 0 },
        { L"gdi32.dll", 0 },
        { L"combase.dll", 0 }
    };

    BOOL bRecognized = TRUE, bIsServer;
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    ULONG testBuildNumber = NtCurrentPeb()->OSBuildNumber;

    ULONG majorVersion = 0, minorVersion = 0, buildNumber = 0;

    //
    // Cross-check of system component versions.
    //

    for (int i = 0; i < RTL_NUMBER_OF(DllData); i++) {
        HMODULE hModule = GetModuleHandle(DllData[i].DllName);
        if (hModule) DllData[i].VersionBuildNumber = supParseOSBuildBumber((PVOID)hModule);
    }

    for (int i = 0; i < RTL_NUMBER_OF(DllData); i++) {

        if (DllData[0].VersionBuildNumber != DllData[i].VersionBuildNumber) {

            SkReportVersionResourceBuildNumber(DllData[i].DllName,
                DllData[0].VersionBuildNumber,
                DllData[i].VersionBuildNumber);

        }

    }

    //
    // Validate version numbers and build range.
    //

    RtlGetNtVersionNumbers(&majorVersion, &minorVersion, &buildNumber);
    buildNumber &= 0xffff;

    //
    // PEB vs ntdll cached build cross-check.
    //
    if (buildNumber != testBuildNumber) {
        SkReportWrongWinVersion((LPWSTR)TEXT("Suspicious Windows build number (PEB/Rtl mismatch)"),
            majorVersion,
            minorVersion,
            testBuildNumber,
            DT_BUILDNUMBER);
        bRecognized = FALSE;
    }

    //
    // Validate that the build number is acceptable for the reported major/minor.
    //
    if (!SkpIsBuildAcceptableForVersion(majorVersion, minorVersion, buildNumber)) {
        SkReportWrongWinVersion((LPWSTR)TEXT("Suspicious Windows version (build invalid for major/minor)"),
            majorVersion,
            minorVersion,
            buildNumber,
            DT_WINVERSION);
        bRecognized = FALSE;
    }

    //
    // ntdll resource build vs PEB build. Enablement packages keep the base build
    // in file resources (18362->18363, 19041->19045, 22621->22631, 26100->26300),
    // so allow same feature pack family drift.
    //
    if (DllData[0].VersionBuildNumber != 0 &&
        DllData[0].VersionBuildNumber != testBuildNumber &&
        !IS_SAME_FEATURE_PACK_FAMILY(DllData[0].VersionBuildNumber, testBuildNumber)) {

        SkReportWrongWinVersion((LPWSTR)TEXT("Suspicious Windows build number (ntdll resource mismatch)"),
            majorVersion,
            minorVersion,
            testBuildNumber,
            DT_BUILDNUMBER);
        bRecognized = FALSE;
    }

    //
    // SharedUserData->NtBuildNumber is kernel-fed and read-only in user mode.
    // Only valid on Win10+ (on 6.x this offset is reserved). Mask as for reference.
    //
    if (majorVersion == 10) {
        ULONG sharedBuild = USER_SHARED_DATA->NtBuildNumber & 0xffff;
        if (sharedBuild != testBuildNumber &&
            !IS_SAME_FEATURE_PACK_FAMILY(sharedBuild, testBuildNumber)) {
            SkReportWrongWinVersion((LPWSTR)TEXT("Suspicious Windows build number (SharedUserData/PEB mismatch)"),
                majorVersion,
                minorVersion,
                testBuildNumber,
                DT_BUILDNUMBER);
            bRecognized = FALSE;
        }
    }

    //
    // Domain controllers report NtProductLanManNt, not NtProductServer.
    //

    bIsServer = (USER_SHARED_DATA->NtProductType == NtProductServer ||
        USER_SHARED_DATA->NtProductType == NtProductLanManNt);

    if (bRecognized && majorVersion == 10 && testBuildNumber > NT_WIN10_22H2) {
        if (bIsServer) {
            bRecognized = IS_WINSRV_ONLY_BUILD(testBuildNumber) ||   // 20348 (2022), 25398 (23H2 AC)
                (testBuildNumber == NT_WIN11_24H2);        // 26100 (Server 2025)
        }
        else {
            bRecognized = !IS_WINSRV_ONLY_BUILD(testBuildNumber);
        }

        if (!bRecognized) {
            SkReportWrongWinVersion((LPWSTR)TEXT("Suspicious Windows version (SKU/build mismatch)"),
                majorVersion,
                minorVersion,
                testBuildNumber,
                DT_WINVERSION);
        }
    }

    //
    // Cross-check with kernel reference build (allow feature pack family drift).
    //

    if (Context->ReferenceNtBuildNumber) {

        //
        // Reference is the kernel base. It must equal the exact expected base for
        // the reported build. This subsumes the IsFeaturePack flag for this check.
        //
        if (Context->ReferenceNtBuildNumber != SkpExpectedKernelBaseBuild(testBuildNumber)) {
            SkReportWrongWinVersion((LPWSTR)TEXT("Suspicious Windows build number (kernel reference)"),
                majorVersion,
                minorVersion,
                testBuildNumber,
                DT_BUILDNUMBER);
        }

        if (!(Context->IsFeaturePack && IS_SAME_FEATURE_PACK_FAMILY(Context->ReferenceNtBuildNumber, testBuildNumber))) {
            if (Context->ReferenceNtBuildNumber != testBuildNumber) {
                SkReportWrongWinVersion((LPWSTR)TEXT("Suspicious Windows build number"),
                    majorVersion,
                    minorVersion,
                    testBuildNumber,
                    DT_BUILDNUMBER);
            }
        }
    }

    //
    // Syscall layout.
    //

    PVOID ntdllBase;
    ULONG dllChars = IMAGE_FILE_EXECUTABLE_IMAGE;
    UNICODE_STRING dllName;

    RtlInitUnicodeString(&dllName, RtlNtdllName);
    NTSTATUS ntStatus = LdrGetDllHandle(NULL, &dllChars, &dllName, &ntdllBase);
    if (NT_SUCCESS(ntStatus)) {
        if (!SkpValidateSyscallLayoutForVersionData((HMODULE)ntdllBase, testBuildNumber)) {
            SkReportWrongWinVersion((LPWSTR)TEXT("Tampered Windows build number (Syscall Layout)"),
                majorVersion,
                minorVersion,
                testBuildNumber,
                DT_BUILDNUMBER);
        }
    }
    else {
        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Failed to query ntdll base"),
            (LPWSTR)__FUNCTIONW__,
            NULL);
    }

    BOOL bValid = FALSE;
    if (SUCCEEDED(SkpValidateVersionDataWMI(majorVersion, minorVersion, testBuildNumber, &bValid))) {

        if (bValid == FALSE) {
            SkReportWrongWinVersion((LPWSTR)TEXT("Windows version data tampering detected (WMI Query)"),
                majorVersion,
                minorVersion,
                testBuildNumber,
                DT_WINVERSION);
        }
    } //func will throw errors automatically.

    return (SkiGetAnomalyCount() == oldAnomalyCount);
}
