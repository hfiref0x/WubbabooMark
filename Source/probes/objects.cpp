/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       OBJECTS.CPP
*
*  VERSION:     1.00
*
*  DATE:        04 Jul 2023
*
*  System object handles probes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

BOOL SkIsThreadInformationTampered(
    _In_ BOOL SuppressOutput,
    _In_ HANDLE FirstObjectHandle,
    _In_ HANDLE SecondObjectHandle
)
{
    NTSTATUS ntStatus;
    ntStatus = NtCompareObjects(FirstObjectHandle,
        SecondObjectHandle);

    if (!NT_SUCCESS(ntStatus)) {

        if (!SuppressOutput) {
            LPWSTR lpText;

            if (ntStatus == STATUS_NOT_SAME_OBJECT) {
                lpText = (LPWSTR)TEXT("Thread information tampered");
            }
            else {
                lpText = (LPWSTR)TEXT("Failed verify handle equality");
            }

            SkReportNtCallRIP(ntStatus,
                lpText,
                (LPWSTR)__FUNCTIONW__,
                NULL);
        }
        return TRUE;
    }

    return FALSE;
}

VOID SkiQueryAndValidateHandleInformation(
    _In_ BOOL IsProcess,
    _In_ PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX HandleEntry
)
{
    NTSTATUS ntStatus;
    HANDLE hProcess = NULL, hObject = NULL;
    OBJECT_ATTRIBUTES obja;
    CLIENT_ID cid;

    ACCESS_MASK desiredAccess;

    if (IsProcess)
        desiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;
    else
        desiredAccess = THREAD_QUERY_LIMITED_INFORMATION;

    InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (HANDLE)HandleEntry->UniqueProcessId;
    cid.UniqueThread = NULL;

    // 
    // Insignificant failure, we maybe lacking enough privs to do that.
    //
    ntStatus = NtOpenProcess(&hProcess, PROCESS_DUP_HANDLE, &obja, &cid);
    if (NT_SUCCESS(ntStatus)) {

        //
        // Insignificant failure also.
        //
        ntStatus = NtDuplicateObject(hProcess,
            (HANDLE)HandleEntry->HandleValue,
            NtCurrentProcess(),
            &hObject,
            desiredAccess,
            0,
            0);

        if (NT_SUCCESS(ntStatus)) {

            ntStatus = NtCompareObjects(IsProcess ? NtCurrentProcess() : NtCurrentThread(), hObject);
            if (NT_SUCCESS(ntStatus)) {

                //
                // Handle is us.
                //
                if (IsProcess) {
                    if ((HandleEntry->GrantedAccess & PROCESS_VM_WRITE) ||
                        HandleEntry->GrantedAccess & PROCESS_SUSPEND_RESUME) 
                    {
                        SkReportSuspectHandleEntry(TRUE, HandleEntry);
                    }
                }
                else {
                    if ((HandleEntry->GrantedAccess & THREAD_SET_CONTEXT) ||
                        (HandleEntry->GrantedAccess & THREAD_GET_CONTEXT))
                    {
                        SkReportSuspectHandleEntry(FALSE, HandleEntry);
                    }
                }
            }

            NtClose(hObject);
        }
        NtClose(hProcess);
    }
}

BOOL SkiRetrieveOwnHandleTypesInformation(
    _In_ PROBE_CONTEXT* Context,
    _Out_ PULONG DebugObjectTypeIndex,
    _Out_ PULONG ProcessObjectTypeIndex,
    _Out_ PULONG ThreadObjectTypeIndex,
    _Out_ PHANDLE ProcessHandle,
    _Out_opt_ PHANDLE ThreadHandle
)
{
    BOOL bResult = FALSE;
    NTSTATUS ntStatus;
    ULONG returnLength = 0, dbgObjType = MAXULONG32, procObjType = MAXULONG32, threadObjType = MAXULONG32;
    HANDLE dbgObjRef = NULL, procObjRef = NULL, threadObjRef = NULL;

    OBJECT_ATTRIBUTES obja;
    CLIENT_ID cid;

    PPROCESS_HANDLE_SNAPSHOT_INFORMATION pHandleSnapshot = NULL;
    PPROCESS_HANDLE_TABLE_ENTRY_INFO pHandleEntry;

    do {

        InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
        ntStatus = NtCreateDebugObject(&dbgObjRef, DEBUG_ALL_ACCESS, &obja, 0);
        if (!NT_SUCCESS(ntStatus)) {

            SkReportNtCallRIP(ntStatus,
                (LPWSTR)TEXT("Failed to create debug object"),
                (LPWSTR)TEXT("NtCreateDebugObject"),
                NULL);

            break;
        }

        //
        // Duplicate CLIENT_ID check as it was done in SkValidateClientInfo however this one will
        // output wubbaboo warning.
        //

        cid = Context->ClientId;
        ntStatus = NtOpenThread(&threadObjRef, SYNCHRONIZE, &obja, &cid);
        if (!NT_SUCCESS(ntStatus)) {

            SkReportNtCallRIP(ntStatus,
                (LPWSTR)TEXT("Failed to open own thread"),
                (LPWSTR)TEXT("NtOpenThread"),
                NULL);

            break;
        }

        if (SkIsThreadInformationTampered(FALSE, NtCurrentThread(), threadObjRef))
            break;

        cid.UniqueThread = NULL;
        ntStatus = NtOpenProcess(&procObjRef, SYNCHRONIZE, &obja, &cid);
        if (!NT_SUCCESS(ntStatus)) {

            SkReportNtCallRIP(ntStatus,
                (LPWSTR)TEXT("Failed to open own process"),
                (LPWSTR)TEXT("NtOpenProcess"),
                NULL);

            break;
        }

        if (SkIsThreadInformationTampered(FALSE, NtCurrentProcess(), procObjRef))
            break;

        pHandleSnapshot = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)supGetProcessInfoVariableSize(
            ProcessHandleInformation,
            &returnLength);

        if (pHandleSnapshot == NULL) {

            SkReportNtCallRIP(STATUS_MEMORY_NOT_ALLOCATED,
                (LPWSTR)TEXT("Failed to query own handles information"),
                (LPWSTR)TEXT("NtQueryInformationProcess"),
                NULL);

            break;
        }

        SIZE_T expectedLength = FIELD_OFFSET(PROCESS_HANDLE_SNAPSHOT_INFORMATION, Handles) +
            (pHandleSnapshot->NumberOfHandles * sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO));
        if (expectedLength != returnLength) {
            SkReportHandleListCorruption(returnLength, (ULONG)expectedLength);
        }

        for (ULONG i = 0; i < pHandleSnapshot->NumberOfHandles; i++) {
            pHandleEntry = &pHandleSnapshot->Handles[i];

            if (pHandleEntry->HandleValue == dbgObjRef && dbgObjType == MAXULONG32)
                dbgObjType = pHandleEntry->ObjectTypeIndex;

            if (pHandleEntry->HandleValue == procObjRef && procObjType == MAXULONG32)
                procObjType = pHandleEntry->ObjectTypeIndex;

            if (pHandleEntry->HandleValue == threadObjRef && threadObjType == MAXULONG32)
                threadObjType = pHandleEntry->ObjectTypeIndex;

            bResult = ((dbgObjType != MAXULONG32) &&
                (procObjType != MAXULONG32) && 
                (threadObjType != MAXULONG32));

            if (bResult)
                break;
        }

    } while (FALSE);

    if (pHandleSnapshot) supHeapFree(pHandleSnapshot);
    if (dbgObjRef) NtClose(dbgObjRef);

    if (!bResult) {
        if (procObjRef) NtClose(procObjRef);
        if (threadObjRef) NtClose(threadObjRef);
        procObjRef = NULL;
        threadObjRef = NULL;
    }

    if (ThreadHandle) {
        *ThreadHandle = threadObjRef;
    } 
    else {
        if (threadObjRef) NtClose(threadObjRef);
    }

    *ProcessHandle = procObjRef;
    *DebugObjectTypeIndex = dbgObjType;
    *ProcessObjectTypeIndex = procObjType;
    *ThreadObjectTypeIndex = threadObjType;

    return bResult;
}

/*
* SkCheckHandles
*
* Purpose:
*
* Analyze handle dump.
*
*/
BOOL SkCheckHandles(
    _In_ PROBE_CONTEXT* Context
)
{
    NTSTATUS ntStatus;
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    PSYSTEM_HANDLE_INFORMATION_EX handleArray = NULL;
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX pHandleEntry;
    POBJECT_TYPES_INFORMATION pObjectTypes;
    HANDLE processObjectHandle = NULL, threadObjectHandle = NULL;

    ULONG dbgObjType, procObjType, threadObjType;
    ULONG i, returnLength;
    SIZE_T expectedLength;

    POBJECT_TYPE_INFORMATION pObject;

    union {
        union {
            POBJECT_TYPE_INFORMATION Object;
            POBJECT_TYPE_INFORMATION_V2 ObjectV2;
        } u1;
        PBYTE Ref;
    } ObjectTypeEntry;

    do {

        if (!SkiRetrieveOwnHandleTypesInformation(
            Context,
            &dbgObjType,
            &procObjType,
            &threadObjType,
            &processObjectHandle,
            &threadObjectHandle))
        {
            break;
        }

        returnLength = NULL;
        handleArray = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, &returnLength);
        if (handleArray == NULL) {

            SkReportNtCallRIP(STATUS_MEMORY_NOT_ALLOCATED,
                (LPWSTR)TEXT("Failed to query handle information"),
                (LPWSTR)TEXT("NtQuerySystemInformation"),
                (LPWSTR)TEXT("SystemExtendedHandleInformation"));

            break;
        }

        expectedLength = FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION_EX, Handles) +
            (handleArray->NumberOfHandles * sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
        if (expectedLength != returnLength) {
            SkReportHandleListCorruption(returnLength, (ULONG)expectedLength);
        }

        ULONG debugObjectHandleCount = 0;
        ULONG currentProcessId = HandleToUlong(Context->ClientId.UniqueProcess);

        for (i = 0; i < handleArray->NumberOfHandles; i++) {

            pHandleEntry = &handleArray->Handles[i];

            if (pHandleEntry->ObjectTypeIndex == procObjType) {
                if (pHandleEntry->UniqueProcessId != currentProcessId) {
                    SkiQueryAndValidateHandleInformation(TRUE, pHandleEntry);
                }
            }

            if (pHandleEntry->ObjectTypeIndex == threadObjType) {
                if (pHandleEntry->UniqueProcessId != currentProcessId) {
                    SkiQueryAndValidateHandleInformation(FALSE, pHandleEntry);
                }
            }
            
            //
            // This is ambiguous detection, however why not?
            //
            if (pHandleEntry->ObjectTypeIndex == dbgObjType)
                debugObjectHandleCount++;

        }

        if (debugObjectHandleCount > 0)
            SkReportDebugObject(debugObjectHandleCount, TRUE);

        //
        // NtQueryObject handle compare.
        //

        ULONG handleCount = 0, objectsCount = 0;

        ntStatus = supGetObjectTypesInfo(&returnLength, (PVOID*)&pObjectTypes);
        if (NT_SUCCESS(ntStatus)) {

            __try {

                BOOL bObjFound = FALSE;
                ULONG size;

                pObject = OBJECT_TYPES_FIRST_ENTRY(pObjectTypes);
                size = ALIGN_UP(sizeof(OBJECT_TYPES_INFORMATION), ULONG_PTR);

                for (i = 0; i < pObjectTypes->NumberOfTypes; i++) {

                    ObjectTypeEntry.Ref = (PBYTE)pObject;

                    if (!bObjFound) {

                        if (Context->WindowsMajorVersion >= 8) {
                            if (ObjectTypeEntry.u1.ObjectV2->TypeIndex == dbgObjType) {
                                handleCount = ObjectTypeEntry.u1.ObjectV2->TotalNumberOfHandles;
                                objectsCount = ObjectTypeEntry.u1.ObjectV2->TotalNumberOfObjects;
                                bObjFound = TRUE;
                            }
                        }
                        else {
                            if ((i + 2) == dbgObjType) {
                                handleCount = ObjectTypeEntry.u1.Object->TotalNumberOfHandles;
                                objectsCount = ObjectTypeEntry.u1.Object->TotalNumberOfObjects;
                                bObjFound = TRUE;
                            }
                        }

                    }

                    size += sizeof(OBJECT_TYPE_INFORMATION);
                    size += ALIGN_UP(ObjectTypeEntry.u1.Object->TypeName.MaximumLength, ULONG_PTR);

                    pObject = OBJECT_TYPES_NEXT_ENTRY(pObject);
                }

                if (size != returnLength) {
                    SkReportObTypeListCorruption(returnLength, size);
                }

            }
            __except (EXCEPTION_EXECUTE_HANDLER) {

                SkReportNtCallRIP(GetExceptionCode(),
                    (LPWSTR)TEXT("Exception during traversing objects list"),
                    (LPWSTR)TEXT("SkCheckDebugObjects"),
                    NULL);

            }

            //
            // Check a lazy filtering.
            //

            if (handleCount != debugObjectHandleCount) {
                SkReportDebugObjectHandleMismatch(handleCount, debugObjectHandleCount);
            }

            if (objectsCount > 0) {
                SkReportDebugObject(objectsCount, FALSE);
            }

        }
        else {

            SkReportNtCallRIP(ntStatus,
                (LPWSTR)TEXT("Failed to query object type information"),
                (LPWSTR)TEXT("NtQueryObject"),
                (LPWSTR)TEXT("ObjectTypesInformation"));

        }

    } while (FALSE);

    if (handleArray)
        supHeapFree(handleArray);

    if (processObjectHandle)
        NtClose(processObjectHandle);

    if (threadObjectHandle)
        NtClose(threadObjectHandle);

    return (SkiGetAnomalyCount() == oldAnomalyCount);
}

/*
* SkNoKernelWubbaboos
*
* Purpose:
*
* Detect suspicious driver device objects.
*
*/
BOOL SkNoKernelWubbaboos()
{
    BOOL bResult = TRUE;
    LPWSTR lpWubbabooDevices[] = {
        (LPWSTR)TEXT("HyperHideDrv"),
        (LPWSTR)TEXT("kldbgdrv"),
        (LPWSTR)TEXT("TitanHide"),
        (LPWSTR)TEXT("HyperDbgDebuggerDevice")
    };

    for (ULONG i = 0; i < RTL_NUMBER_OF(lpWubbabooDevices); i++) {
        if (supIsObjectExists((LPCWSTR)TEXT("\\Device"), lpWubbabooDevices[i])) {
            SkReportDeviceObject(lpWubbabooDevices[i]);
            bResult = FALSE;
        }
    }

    return bResult;
}
