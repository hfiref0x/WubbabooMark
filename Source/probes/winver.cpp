/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       WINVER.CPP
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

        if (TestBuildNumber == NT_WIN11_22H2) {
            lpName = (LPCSTR)"NtCreateCpuPartition";
            break;
        }

        //
        // This one could be missing in early win11 previews and dev builds as it was introduced later.
        // It doesn't matter, if you want to play this hard, okay.
        //
        if (TestBuildNumber > NT_WIN11_22H2) {
            lpName = (LPCSTR)"NtAlertThreadByThreadIdEx";
            break;
        }

        lpName = NULL;

    } while (FALSE);

    if (lpName == NULL)
        return NULL;

    return (PVOID)GetProcAddress(NtDllBase, lpName);
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

    BOOL bRecognized = TRUE;
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    ULONG testBuildNumber = NtCurrentPeb()->OSBuildNumber;

    ULONG majorVersion = 0, minorVersion = 0, buildNumber = 0;
    ULONG buildNumberMin = 0, buildNumberMax = 0;

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

    if (majorVersion < 6 || majorVersion > 10) {

        SkReportWrongWinVersion((LPWSTR)TEXT("Suspicious Windows major version"),
            majorVersion,
            minorVersion,
            buildNumber,
            DT_WINVERSION);

    }

    if (minorVersion > 3) {

        //
        // No such exists.
        //

        SkReportWrongWinVersion((LPWSTR)TEXT("Suspicious Windows minor version"),
            majorVersion,
            minorVersion,
            buildNumber,
            DT_WINVERSION);

    }

    //
    // Find valid build range for version.
    // 
    //
    // Windows 7
    //
    if (majorVersion == 6 && minorVersion == 1) {
        buildNumberMin = NT_WIN7_RTM;
        buildNumberMax = NT_WIN7_SP1;
    }
    else {
        //
        // Windows 8/8.1
        //
        if (majorVersion == 6 && minorVersion <= 3) {
            if (minorVersion == 2) {
                //
                // Windows 8.
                //
                buildNumberMin = NT_WIN8_RTM;
                buildNumberMax = NT_WIN8_RTM;
            }
            else
            {
                //
                // Windows 8.1
                //
                if (minorVersion == 3) {
                    buildNumberMin = NT_WIN8_BLUE;
                    buildNumberMax = NT_WIN8_BLUE;
                }
            }

        }
        else {
            //
            // Windows 10+
            //
            if (majorVersion == 10) {
                if (testBuildNumber < NT_WIN10_THRESHOLD1) {
                    bRecognized = FALSE;
                }
                else {
                    if (testBuildNumber > NT_WIN10_22H2) {
                        if (USER_SHARED_DATA->NtProductType == NtProductServer) {
                            buildNumberMin = NT_WINSRV_21H1;
                            buildNumberMax = NT_WINSRV_21H1;
                        }
                        else {
                            buildNumberMin = NT_WIN11_21H2;
                            buildNumberMax = NT_WIN11_24H2;
                        }
                    }
                    else {
                        buildNumberMin = NT_WIN10_THRESHOLD1;
                        buildNumberMax = NT_WIN10_22H2;
                    }
                }
            }
            else {
                bRecognized = FALSE;
            }
        }
    }

    if (bRecognized == FALSE) {

        SkReportWrongWinVersion((LPWSTR)TEXT("Suspicious Windows version"),
            majorVersion,
            minorVersion,
            buildNumber,
            DT_WINVERSION);
    }


    if (buildNumberMin && buildNumberMax) {
        if (!(testBuildNumber >= buildNumberMin && testBuildNumber <= buildNumberMax)) {

            SkReportWrongWinVersion((LPWSTR)TEXT("Suspicious Windows build number"),
                majorVersion,
                minorVersion,
                testBuildNumber,
                DT_BUILDNUMBER);
        }
    }

    if (Context->ReferenceNtBuildNumber) {
        if (!Context->Win10FeaturePack && !IS_WIN10_FEATURE_PACK_RANGE(testBuildNumber)) {
            if (Context->ReferenceNtBuildNumber != testBuildNumber)
                SkReportWrongWinVersion((LPWSTR)TEXT("Suspicious Windows build number"),
                    majorVersion,
                    minorVersion,
                    testBuildNumber,
                    DT_BUILDNUMBER);
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
