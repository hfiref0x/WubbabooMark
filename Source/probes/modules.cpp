/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       MODULES.CPP
*
*  VERSION:     1.00
*
*  DATE:        01 Jul 2023
*
*  Image modules probes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

typedef enum _DLL_REPORT_EVENT {
    NonSystemDll = 0,
    TamperedDll,
    MaxDllReportReport
} DLL_REPORT_EVENT;

typedef VOID(NTAPI* SkpEnumerationOutputCallback)(
    _In_ PLDR_DATA_TABLE_ENTRY DataEntry,
    _In_ DLL_REPORT_EVENT DllEvent
    );

typedef struct _LDR_ENUM_CTX {
    _In_ SkpEnumerationOutputCallback OutputCallback;
    _In_ PPROBE_CONTEXT Context;
} LDR_ENUM_CTX, PLDR_ENUM_CTX;

BOOL SkpValidateLoaderDataEntry(
    _In_ PPROBE_CONTEXT Context,
    _In_ PLDR_DATA_TABLE_ENTRY DataEntry
)
{
    PLDR_DATA_TABLE_ENTRY_FULL dataEntry = (PLDR_DATA_TABLE_ENTRY_FULL)DataEntry;
    OBJECT_NAME_INFORMATION* objectNameInfo = NULL;
    SIZE_T size;
    LPWSTR lpWin32Name = NULL;
    UNICODE_STRING usFullDllName;
    NTSTATUS ntStatus;
    BOOL bSeemsLegit = FALSE;
    PIMAGE_NT_HEADERS NtHeaders;

    ULONG hashValue = 0;

    do {

        __try {
            if (!NT_SUCCESS(RtlImageNtHeaderEx(0,
                dataEntry->DllBase, dataEntry->SizeOfImage, &NtHeaders)))
            {
                break;
            }

            if (dataEntry->EntryPoint) {
                if (!IN_REGION(dataEntry->EntryPoint, dataEntry->DllBase, dataEntry->SizeOfImage))
                    break;
            }

            //
            // Available since 8+
            //
            if (Context->WindowsMajorVersion >= 8) {
                if (NT_SUCCESS(RtlHashUnicodeString(&dataEntry->BaseDllName,
                    TRUE,
                    HASH_STRING_ALGORITHM_X65599,
                    &hashValue)))
                {
                    if (hashValue != dataEntry->BaseNameHashValue)
                        break;
                }
                else {
                    break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }

        UNICODE_STRING ntFileName;
        PVOID mappedImage = NULL;

        //
        // Compare control area data.
        //
        if (RtlDosPathNameToNtPathName_U(dataEntry->FullDllName.Buffer, 
            &ntFileName, 
            NULL, 
            NULL)) 
        {
            ntStatus = supMapImageNoExecute(&ntFileName, &mappedImage);
            if (NT_SUCCESS(ntStatus)) {

                ntStatus = NtAreMappedFilesTheSame(dataEntry->DllBase, mappedImage);
                if (!NT_SUCCESS(ntStatus)) {
                    SkReportNtCallRIP(ntStatus,
                        (LPWSTR)TEXT("Loader entry FullDllName is tampered"),
                        (LPWSTR)__FUNCTIONW__,
                        NULL);
                }
                else {
                    bSeemsLegit = TRUE;
                }

                NtUnmapViewOfSection(NtCurrentProcess(), mappedImage);
            }
            else {
                SkReportNtCallRIP(ntStatus,
                    (LPWSTR)TEXT("Failed to map loader entry"),
                    (LPWSTR)TEXT("supMapImageNoExecute"),
                    NULL);
            }

            RtlFreeUnicodeString(&ntFileName);
        }
        else {
            //
            // The conversion has failed, switch to trivial comparison.
            //
            ntStatus = supGetMappedFileName(dataEntry->DllBase, &objectNameInfo);
            if (!NT_SUCCESS(ntStatus)) {
                SkReportNtCallRIP(ntStatus,
                    (LPWSTR)TEXT("Failed to query mapped filename"),
                    (LPWSTR)TEXT("supGetMappedFileName"),
                    NULL);
            }

            if (objectNameInfo == NULL)
                break;

            //
            // Check mapped fileName against DataEntry->FullDllName.
            //
            size = UNICODE_STRING_MAX_CHARS * sizeof(WCHAR);
            lpWin32Name = (LPWSTR)supHeapAlloc(size);

            if (lpWin32Name) {

                if (supConvertFileName(objectNameInfo->Name.Buffer,
                    lpWin32Name,
                    size / sizeof(WCHAR)))
                {
                    RtlInitUnicodeString(&usFullDllName, lpWin32Name);
                    bSeemsLegit = RtlEqualUnicodeString(&dataEntry->FullDllName, &usFullDllName, TRUE);
                }

                supHeapFree(lpWin32Name);
            }
        }

    } while (FALSE);

    if (objectNameInfo) supHeapFree(objectNameInfo);
    return bSeemsLegit;
}

/*
* SkpLdrEnumModulesCallback
*
* Purpose:
*
* Callback of LdrEnumerateLoadedModuels, check if module has system origin.
*
*/
VOID NTAPI SkpLdrEnumModulesCallback(
    _In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    _In_ PVOID Context,
    _Inout_ BOOLEAN* StopEnumeration
)
{
    NTSTATUS ntStatus;
    LDR_ENUM_CTX* enumContext = (LDR_ENUM_CTX*)Context;
    PVOID selfImageBase = enumContext->Context->SelfBase;
    SkpEnumerationOutputCallback callback = enumContext->OutputCallback;

    if (DataTableEntry->DllBase != selfImageBase) {

        ntStatus = supVerifyFileSignature(
            UserMode, 
            DataTableEntry->FullDllName.Buffer,
            FALSE,
            enumContext->Context->WTGetSignatureInfo);

        if (!NT_SUCCESS(ntStatus)) {

            SkiIncreaseAnomalyCount();
            callback(DataTableEntry, NonSystemDll);

        }
        else {
            //
            // File is signed, but is PEB loader information correct?
            //
            if (!SkpValidateLoaderDataEntry(enumContext->Context, DataTableEntry)) {
                SkiIncreaseAnomalyCount();
                callback(DataTableEntry, TamperedDll);
            }
        }
    }

    *StopEnumeration = FALSE;
}

VOID SkpLdrEnumerateOutput(
    _In_ PLDR_DATA_TABLE_ENTRY DataEntry,
    _In_ DLL_REPORT_EVENT DllEvent
)
{
    WCHAR szAddress[32];

    LPWSTR lpName;
    SIZE_T length = MAX_TEXT_LENGTH + (SIZE_T)DataEntry->FullDllName.MaximumLength;

    lpName = (LPWSTR)supHeapAlloc(length);
    if (lpName) {

        RtlSecureZeroMemory(&szAddress, sizeof(szAddress));

        if (DllEvent == NonSystemDll) {

            StringCchPrintf(lpName,
                length / sizeof(WCHAR),
                TEXT("Non system module %ws"),
                DataEntry->FullDllName.Buffer);

        }
        else {
            StringCchPrintf(lpName,
                length / sizeof(WCHAR),
                TEXT("Tampered module %ws"),
                DataEntry->FullDllName.Buffer);

        }

        StringCchPrintf(szAddress,
            RTL_NUMBER_OF(szAddress),
            TEXT("0x%llX"),
            (ULONG_PTR)DataEntry->DllBase);

        supReportEvent(evtDetection,
            lpName,
            szAddress,
            DT_3RDPARTYCODE);

        supHeapFree(lpName);
    }
}

/*
* SkWalkPEB
*
* Purpose:
*
* Walk PEB loaded and check if modules have system origin.
*
*/
BOOL SkWalkPEB(
    _In_ PPROBE_CONTEXT Context
)
{
    LDR_ENUM_CTX enumContext;
    ULONG oldAnomalyCount = SkiGetAnomalyCount();

    enumContext.OutputCallback = (SkpEnumerationOutputCallback)SkpLdrEnumerateOutput;
    enumContext.Context = Context;

    LdrEnumerateLoadedModules(0,
        (PLDR_LOADED_MODULE_ENUMERATION_CALLBACK_FUNCTION)&SkpLdrEnumModulesCallback,
        (PVOID)&enumContext);

    return (oldAnomalyCount == SkiGetAnomalyCount());
}

/*
* SkWalkLoadedDrivers
*
* Purpose:
*
* Walk loaded kernel module list and check if modules are properly signed.
*
*/
BOOL SkWalkLoadedDrivers(
    _In_ PPROBE_CONTEXT Context
)
{
    NTSTATUS ntStatus;
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    ULONG returnedLength = 0, expectedLength;
    PRTL_PROCESS_MODULES pModulesList = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(FALSE, &returnedLength);
    PRTL_PROCESS_MODULE_INFORMATION moduleEntry;
    UNICODE_STRING fileName;
    LPWSTR lpWin32Name = NULL;

    if (pModulesList) {

        //
        // Lazy alteration check.
        //
        expectedLength = ((pModulesList->NumberOfModules * sizeof(RTL_PROCESS_MODULE_INFORMATION)) +
            FIELD_OFFSET(RTL_PROCESS_MODULES, Modules));

        if (returnedLength != expectedLength)
            SkReportDriverListModification(returnedLength, expectedLength);

        //
        // Braindead alteration check.
        //
        if (pModulesList->NumberOfModules < 16) {
            
            SkiIncreaseAnomalyCount();
            supReportEvent(evtDetection,
                (LPWSTR)TEXT("Invalid number of entries in modules list"),
                (LPWSTR)TEXT("NtQuerySystemInformation"),
                (LPWSTR)TEXT("SystemModuleInformation"));

        }

        for (ULONG i = 0; i < pModulesList->NumberOfModules; i++) {

            moduleEntry = &pModulesList->Modules[i];
            RtlInitEmptyUnicodeString(&fileName, NULL, 0);

            ntStatus = supConvertToUnicode(
                (LPCSTR)&moduleEntry->FullPathName,
                &fileName);

            if (NT_SUCCESS(ntStatus)) {
                if (fileName.Buffer != NULL) {
                    ntStatus = supGetWin32FileName(fileName.Buffer, &lpWin32Name);
                    if (NT_SUCCESS(ntStatus)) {

                        ntStatus = supVerifyFileSignature(KernelMode, 
                            lpWin32Name, 
                            FALSE, 
                            Context->WTGetSignatureInfo);
                        
                        if (!NT_SUCCESS(ntStatus)) {

                            SkiIncreaseAnomalyCount();

                            supReportEvent(evtWarning,
                                lpWin32Name,
                                (LPWSTR)TEXT("WinTrust"),
                                DT_SIGNATURE_INVALID);

                        }

                        supHeapFree(lpWin32Name);
                    }
                    else {
                        if (ntStatus != STATUS_OBJECT_NAME_NOT_FOUND) {

                            SkReportNtCallRIP(ntStatus,
                                (LPWSTR)TEXT("Failed to open driver file"),
                                (LPWSTR)TEXT("supGetWin32FileName"),
                                NULL);

                        }
                    }
                }
                RtlFreeUnicodeString(&fileName);
            }
            else {

                SkReportNtCallRIP(ntStatus,
                    (LPWSTR)TEXT("Failed to convert driver file to UNICODE"),
                    (LPWSTR)TEXT("supConvertToUnicode"),
                    NULL);
            }

        }
        supHeapFree(pModulesList);
    }
    else {

        SkReportNtCallRIP(STATUS_UNSUCCESSFUL,
            (LPWSTR)TEXT("Failed to query loaded modules list"),
            (LPWSTR)TEXT("NtQuerySystemInformation"),
            (LPWSTR)TEXT("SystemModuleInformation"));

    }

    return (SkiGetAnomalyCount() == oldAnomalyCount);
}
