/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025 - 2026
*
*  TITLE:       ETW.CPP
*
*  VERSION:     1.50
*
*  DATE:        22 Nov 2026
*
*  ETW probes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

//
// Microsoft-Windows-Win32k {8C416C79-D49B-4F01-A467-E56D3AA8234C}
//
static const GUID SkEtwp_Win32kProvider =
{
    0x8c416c79, 0xd49b, 0x4f01,
    { 0xa4, 0x67, 0xe5, 0x6d, 0x3a, 0xa8, 0x23, 0x4c }
};

//
// Private session GUID.
//
static const GUID SkEtwp_SessionGuid =
{
    0x4b8d5a17, 0x7d2c, 0x4b64,
    { 0x91, 0x2a, 0x5c, 0x72, 0x61, 0x4f, 0x38, 0x91 }
};

static const WCHAR SkEtwp_SessionName[] = L"WubbabooSession";
#define SKETWP_SESSION_PROPERTIES_SIZE \
    (sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SkEtwp_SessionName))

typedef struct _SK_ETW_EVIDENCE {
    DWORD EntityId;              // PID or TID
    ULONG HitCount;
    WCHAR EventName[64];
    WCHAR PropertyName[64];
} SK_ETW_EVIDENCE, * PSK_ETW_EVIDENCE;

typedef struct _SK_ETW_EVIDENCE_LIST {
    ULONG Count;
    ULONG Capacity;
    PSK_ETW_EVIDENCE Items;
} SK_ETW_EVIDENCE_LIST, * PSK_ETW_EVIDENCE_LIST;

typedef struct _SK_ETW_COLLECTOR_CONTEXT {
    TRACEHANDLE SessionHandle;
    TRACEHANDLE TraceHandle;
    HANDLE ConsumerThread;
    volatile LONG ConsumerReady;
    volatile LONG ConsumerFinished;
    SK_ETW_EVIDENCE_LIST Pids;
    SK_ETW_EVIDENCE_LIST Tids;
} SK_ETW_COLLECTOR_CONTEXT, * PSK_ETW_COLLECTOR_CONTEXT;

/*
* SkEtwpFreeEvidenceList
*
* Purpose:
*
* Frees the memory of an ETW evidence list and resets its state.
*
*/
VOID SkEtwpFreeEvidenceList(
    _Inout_ PSK_ETW_EVIDENCE_LIST List
)
{
    if (List == NULL)
        return;

    if (List->Items) {
        supHeapFree(List->Items);
        List->Items = NULL;
    }

    List->Count = 0;
    List->Capacity = 0;
}

/*
* SkEtwpFindEvidence
*
* Purpose:
*
* Searches for an existing evidence entry by its EntityId (PID/TID).
*
*/
PSK_ETW_EVIDENCE SkEtwpFindEvidence(
    _In_ PSK_ETW_EVIDENCE_LIST List,
    _In_ DWORD EntityId
)
{
    ULONG i;

    if (List == NULL)
        return NULL;

    for (i = 0; i < List->Count; i++) {
        if (List->Items[i].EntityId == EntityId)
            return &List->Items[i];
    }

    return NULL;
}

/*
* SkEtwpRecordEvidence
*
* Purpose:
*
* Records or updates an ETW evidence entry, dynamically resizing the list if needed.
*
*/
BOOL SkEtwpRecordEvidence(
    _Inout_ PSK_ETW_EVIDENCE_LIST List,
    _In_ DWORD EntityId,
    _In_opt_ LPCWSTR EventName,
    _In_opt_ LPCWSTR PropertyName
)
{
    ULONG newCap;
    PSK_ETW_EVIDENCE entry, newItems;

    if (List == NULL || EntityId == 0)
        return FALSE;

    entry = SkEtwpFindEvidence(List, EntityId);
    if (entry) {
        entry->HitCount++;
        return TRUE;
    }

    if (List->Count == List->Capacity) {

        if (List->Capacity == 0)
            newCap = 32;
        else {
            if (List->Capacity > (ULONG_MAX / 2))
                return FALSE;

            newCap = List->Capacity * 2;
        }

        if ((SIZE_T)newCap > (MAXULONG_PTR / sizeof(SK_ETW_EVIDENCE)))
            return FALSE;

        newItems = (PSK_ETW_EVIDENCE)supHeapAlloc((SIZE_T)newCap * sizeof(SK_ETW_EVIDENCE));
        if (newItems == NULL)
            return FALSE;

        if (List->Items) {
            RtlCopyMemory(newItems,
                List->Items,
                (SIZE_T)List->Count * sizeof(SK_ETW_EVIDENCE));
            supHeapFree(List->Items);
        }

        List->Items = newItems;
        List->Capacity = newCap;
    }

    entry = &List->Items[List->Count++];
    entry->EntityId = EntityId;
    entry->HitCount = 1;
    entry->EventName[0] = 0;
    entry->PropertyName[0] = 0;

    if (EventName) {
        StringCchCopy(entry->EventName,
            RTL_NUMBER_OF(entry->EventName),
            EventName);
    }

    if (PropertyName) {
        StringCchCopy(entry->PropertyName,
            RTL_NUMBER_OF(entry->PropertyName),
            PropertyName);
    }

    return TRUE;
}

/*
* SkEtwpIsPidProperty
*
* Purpose:
*
* Checks if a given property name corresponds to a Process ID.
*
*/
BOOL SkEtwpIsPidProperty(
    _In_ LPCWSTR Name
)
{
    static const LPCWSTR processNames[] =
    {
        L"ProcessId",
        L"ProcessIdOwningFocus",
        L"OldProcessId",
        L"NewProcessId",
        L"CursorProcessId",
        L"PidReceiver",
        L"SourceProcessId",
        L"Pid",
        L"CallerPid",
        L"OwnerPid",
        L"IdEventProcess"
    };

    ULONG i;

    if (Name == NULL)
        return FALSE;

    for (i = 0; i < RTL_NUMBER_OF(processNames); i++) {

        if (CompareStringOrdinal(Name, -1,
            processNames[i], -1,
            TRUE) == CSTR_EQUAL)
        {
            return TRUE;
        }
    }

    return FALSE;
}

/*
* SkEtwpIsTidProperty
*
* Purpose:
*
* Checks if a given property name corresponds to a Thread ID.
*
*/
BOOL SkEtwpIsTidProperty(
    _In_ LPCWSTR Name
)
{
    static const LPCWSTR threadNames[] =
    {
        L"ThreadId",
        L"OldThreadId",
        L"NewThreadId",
        L"CursorThreadId",
        L"SenderTid",
        L"TidReceiver",
        L"SourceThreadId",
        L"IdEventThread"
    };

    ULONG i;

    if (Name == NULL)
        return FALSE;

    for (i = 0; i < RTL_NUMBER_OF(threadNames); i++) {

        if (CompareStringOrdinal(Name, -1,
            threadNames[i], -1,
            TRUE) == CSTR_EQUAL)
        {
            return TRUE;
        }
    }

    return FALSE;
}

/*
* SkEtwpReadPropertyAsUInt64
*
* Purpose:
*
* Reads a specified property from an ETW event record as a 64-bit unsigned integer.
*
*/
BOOL SkEtwpReadPropertyAsUInt64(
    _In_  PEVENT_RECORD EventRecord,
    _In_  LPCWSTR PropertyName,
    _Out_ PULONGLONG Value
)
{
    ULONG status, size;
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONGLONG buffer;

    if (EventRecord == NULL ||
        PropertyName == NULL ||
        Value == NULL)
    {
        return FALSE;
    }

    *Value = 0;

    RtlZeroMemory(&descriptor, sizeof(descriptor));

    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)PropertyName;
    descriptor.ArrayIndex = ULONG_MAX;

    status = TdhGetPropertySize(EventRecord,
        0,
        NULL,
        1,
        &descriptor,
        &size);

    if (status != ERROR_SUCCESS)
        return FALSE;

    if (size == 0 || size > sizeof(ULONGLONG))
        return FALSE;

    buffer = 0;

    status = TdhGetProperty(EventRecord,
        0, NULL,
        1,
        &descriptor,
        size,
        (PBYTE)&buffer);

    if (status != ERROR_SUCCESS)
        return FALSE;

    *Value = buffer;

    return TRUE;
}

/*
* SkEtwpDecodeEvent
*
* Purpose:
*
* Decodes an ETW event record, extracting and recording PID/TID evidence from its payload.
*
*/
VOID SkEtwpDecodeEvent(
    _In_ PSK_ETW_COLLECTOR_CONTEXT Context,
    _In_ PEVENT_RECORD EventRecord
)
{
    ULONG i, bufferSize = 0, status;
    DWORD emitterPid;
    PBYTE buffer;
    PTRACE_EVENT_INFO eventInfo;
    PEVENT_PROPERTY_INFO propertyInfo;
    WCHAR eventName[64];

    if (Context == NULL || EventRecord == NULL)
        return;

    //
    // 1. Event header identity.
    //
    emitterPid = EventRecord->EventHeader.ProcessId;

    SkEtwpRecordEvidence(&Context->Pids,
        emitterPid,
        L"<event header>",
        L"ProcessId");

    //
    // 2. Fetch schema to walk PID/TID-valued payload properties.
    //
    status = TdhGetEventInformation(EventRecord,
        0,
        NULL,
        NULL,
        &bufferSize);

    if (status != ERROR_INSUFFICIENT_BUFFER)
        return;

    buffer = (PBYTE)supHeapAlloc(bufferSize);
    if (buffer == NULL)
        return;

    eventInfo = (PTRACE_EVENT_INFO)buffer;

    if (TdhGetEventInformation(EventRecord,
        0,
        NULL,
        eventInfo,
        &bufferSize) != ERROR_SUCCESS)
    {
        supHeapFree(buffer);
        return;
    }

    eventName[0] = 0;

    if (eventInfo->EventNameOffset != 0) {
        StringCchCopy(eventName,
            RTL_NUMBER_OF(eventName),
            (LPCWSTR)RtlOffsetToPointer(buffer, eventInfo->EventNameOffset));
    }

    if (eventName[0] == 0) {
        StringCchPrintf(eventName,
            RTL_NUMBER_OF(eventName),
            L"EventId_%u",
            EventRecord->EventHeader.EventDescriptor.Id);
    }

    //
    // 3. Walk every property of the event schema.
    //
    propertyInfo = eventInfo->EventPropertyInfoArray;

    for (i = 0; i < eventInfo->PropertyCount; i++) {

        ULONGLONG value;
        LPCWSTR propName;
        PEVENT_PROPERTY_INFO Prop = &propertyInfo[i];

        if (Prop->NameOffset == 0)
            continue;

        propName = (LPCWSTR)RtlOffsetToPointer(buffer, Prop->NameOffset);

        if (SkEtwpIsPidProperty(propName)) {

            if (!SkEtwpReadPropertyAsUInt64(EventRecord, propName, &value))
                continue;

            if (value == 0 || value > MAXDWORD)
                continue;

            SkEtwpRecordEvidence(&Context->Pids,
                (DWORD)value,
                eventName,
                propName);

        }
        else if (SkEtwpIsTidProperty(propName)) {

            if (!SkEtwpReadPropertyAsUInt64(EventRecord, propName, &value))
                continue;

            if (value == 0 || value > MAXDWORD)
                continue;

            SkEtwpRecordEvidence(&Context->Tids,
                (DWORD)value,
                eventName,
                propName);
        }
    }

    supHeapFree(buffer);
}

/*
* SkEtwpWin32kEventCallback
*
* Purpose:
*
* ETW callback wrapper that safely decodes events with exception handling.
*
*/
VOID WINAPI SkEtwpWin32kEventCallback(
    _In_ PEVENT_RECORD EventRecord)
{
    __try {
        SkEtwpDecodeEvent((PSK_ETW_COLLECTOR_CONTEXT)EventRecord->UserContext, EventRecord);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        //
        // Do nothing.
        //
    }
}

/*
* SkEtwpStartSession
*
* Purpose:
*
* Initializes and starts a real-time ETW trace session for Win32k.
*
*/
BOOL SkEtwpStartSession(
    _Inout_ PSK_ETW_COLLECTOR_CONTEXT Context
)
{
    ULONG propertiesSize, status;
    PBYTE buffer;
    PEVENT_TRACE_PROPERTIES properties;

    if (Context == NULL)
        return FALSE;

    propertiesSize = SKETWP_SESSION_PROPERTIES_SIZE;
    buffer = (PBYTE)supHeapAlloc(propertiesSize);
    if (buffer == NULL)
        return FALSE;

    properties = (PEVENT_TRACE_PROPERTIES)buffer;

    RtlSecureZeroMemory(properties, propertiesSize);

    properties->Wnode.BufferSize = propertiesSize;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.Guid = SkEtwp_SessionGuid;
    properties->Wnode.ClientContext = 1;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    StringCchCopy((PWSTR)RtlOffsetToPointer(buffer, properties->LoggerNameOffset),
        RTL_NUMBER_OF(SkEtwp_SessionName),
        SkEtwp_SessionName);

    status = StartTrace(&Context->SessionHandle,
        SkEtwp_SessionName,
        properties);

    if (status == ERROR_ALREADY_EXISTS) {

        ControlTrace(0,
            SkEtwp_SessionName,
            properties,
            EVENT_TRACE_CONTROL_STOP);

        Context->SessionHandle = 0;

        status = StartTrace(&Context->SessionHandle,
            SkEtwp_SessionName,
            properties);
    }

    if (status != ERROR_SUCCESS) {
        supHeapFree(buffer);
        return FALSE;
    }

    status = EnableTraceEx2(Context->SessionHandle,
        &SkEtwp_Win32kProvider,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0, 0, 0,
        NULL);

    if (status != ERROR_SUCCESS) {

        ControlTrace(Context->SessionHandle,
            SkEtwp_SessionName,
            properties,
            EVENT_TRACE_CONTROL_STOP);

        Context->SessionHandle = 0;

        supHeapFree(buffer);
        return FALSE;
    }

    supHeapFree(buffer);
    return TRUE;
}

/*
* SkEtwpConsumerThread
*
* Purpose:
*
* Worker thread that processes real-time ETW events until the session stops.
*
*/
DWORD WINAPI SkEtwpConsumerThread(
    _In_ LPVOID Parameter
)
{
    ULONG status;
    PSK_ETW_COLLECTOR_CONTEXT context = (PSK_ETW_COLLECTOR_CONTEXT)Parameter;

    if (context == NULL)
        return ERROR_INVALID_PARAMETER;

    InterlockedExchange(&context->ConsumerReady, 1);

    status = ProcessTrace(&context->TraceHandle, 1, NULL, NULL);

    UNREFERENCED_PARAMETER(status);

    InterlockedExchange(&context->ConsumerFinished, 1);

    return 0;
}

/*
* SkEtwpStartConsumer
*
* Purpose:
*
* Opens the ETW trace and spawns the consumer thread to process events.
*
*/
BOOL SkEtwpStartConsumer(
    _Inout_ PSK_ETW_COLLECTOR_CONTEXT Context
)
{
    EVENT_TRACE_LOGFILE logFile;

    if (Context == NULL)
        return FALSE;

    RtlSecureZeroMemory(&logFile, sizeof(logFile));

    logFile.LoggerName = (LPWSTR)SkEtwp_SessionName;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = SkEtwpWin32kEventCallback;
    logFile.Context = Context;

    Context->TraceHandle = OpenTrace(&logFile);

    if (Context->TraceHandle == INVALID_PROCESSTRACE_HANDLE)
        return FALSE;

    Context->ConsumerThread = CreateThread(NULL, 0,
        SkEtwpConsumerThread,
        Context, 0, NULL);

    if (Context->ConsumerThread == NULL) {

        CloseTrace(Context->TraceHandle);
        Context->TraceHandle = INVALID_PROCESSTRACE_HANDLE;
        return FALSE;
    }

    while (InterlockedCompareExchange(&Context->ConsumerReady, 0, 0) == 0)
        Sleep(1);

    Sleep(100);
    return TRUE;
}

/*
* SkEtwpStopSession
*
* Purpose:
*
* Stops the ETW session, waits for the consumer thread, and cleans up handles.
*
*/
VOID SkEtwpStopSession(
    _Inout_ PSK_ETW_COLLECTOR_CONTEXT Context
)
{
    union {
        EVENT_TRACE_PROPERTIES Header;   // forces correct alignment
        UCHAR Buffer[SKETWP_SESSION_PROPERTIES_SIZE];
    } props;

    if (Context == NULL)
        return;

    if (Context->SessionHandle != 0) {

        RtlSecureZeroMemory(&props, sizeof(props));
        props.Header.Wnode.BufferSize = sizeof(props);
        props.Header.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ControlTrace(Context->SessionHandle,
            SkEtwp_SessionName,
            &props.Header,
            EVENT_TRACE_CONTROL_STOP);

        Context->SessionHandle = 0;
    }

    if (Context->TraceHandle != INVALID_PROCESSTRACE_HANDLE)
        CloseTrace(Context->TraceHandle);

    if (Context->ConsumerThread != NULL) {
        WaitForSingleObject(Context->ConsumerThread, INFINITE);
        CloseHandle(Context->ConsumerThread);
        Context->ConsumerThread = NULL;
    }

    Context->TraceHandle = INVALID_PROCESSTRACE_HANDLE;
}

/*
* SkEtwpBroadcastActivity
*
* Purpose:
*
* Triggers system-wide activity (WM_NULL broadcast) to generate Win32k ETW events.
*
*/
BOOL SkEtwpBroadcastActivity(VOID)
{
    DWORD_PTR dummy = 0;

    if (SendMessageTimeout(HWND_BROADCAST,
        WM_NULL,
        0, 0,
        SMTO_ABORTIFHUNG |
        SMTO_BLOCK |
        SMTO_NOTIMEOUTIFNOTHUNG,
        2000,
        &dummy) == 0)
    {
        return FALSE;
    }

    return TRUE;
}

/*
* SkEtwpCollectWin32kEvidence
*
* Purpose:
*
* Orchestrates the ETW session lifecycle to collect PID/TID evidence.
*
*/
BOOL SkEtwpCollectWin32kEvidence(
    _Out_ PSK_ETW_EVIDENCE_LIST PidList,
    _Out_ PSK_ETW_EVIDENCE_LIST TidList
)
{
    BOOL bResult = FALSE;
    SK_ETW_COLLECTOR_CONTEXT context;

    if (PidList == NULL || TidList == NULL)
        return FALSE;

    PidList->Count = 0;
    PidList->Capacity = 0;
    PidList->Items = NULL;

    TidList->Count = 0;
    TidList->Capacity = 0;
    TidList->Items = NULL;

    RtlSecureZeroMemory(&context, sizeof(context));
    context.TraceHandle = INVALID_PROCESSTRACE_HANDLE;

    do {

        if (!SkEtwpStartSession(&context))
            break;

        if (!SkEtwpStartConsumer(&context))
            break;

        if (!SkEtwpBroadcastActivity())
            break;

        Sleep(1000);
        bResult = TRUE;

    } while (FALSE);

    SkEtwpStopSession(&context);

    if (bResult) {

        *PidList = context.Pids;
        *TidList = context.Tids;

        context.Pids.Items = NULL;
        context.Pids.Count = 0;
        context.Pids.Capacity = 0;

        context.Tids.Items = NULL;
        context.Tids.Count = 0;
        context.Tids.Capacity = 0;
    }

    SkEtwpFreeEvidenceList(&context.Pids);
    SkEtwpFreeEvidenceList(&context.Tids);

    return bResult;
}

/*
* SkReportWin32kEtwHiddenProcess
*
* Purpose:
*
* Reports a detected hidden process referenced by Win32k ETW.
*
*/
VOID SkReportWin32kEtwHiddenProcess(
    _In_ HANDLE UniqueProcessId,
    _In_opt_ LPCWSTR lpEventName,
    _In_opt_ LPCWSTR lpPropertyName,
    _In_ ULONG HitCount
)
{
    WCHAR szDetails[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szDetails,
        RTL_NUMBER_OF(szDetails),
        TEXT("PID: %llu, Event: %ws, Property: %ws, Hits: %lu"),
        (ULONG_PTR)UniqueProcessId,
        lpEventName ? lpEventName : TEXT("?"),
        lpPropertyName ? lpPropertyName : TEXT("?"),
        HitCount);

    supReportEvent(evtDetection,
        (LPWSTR)TEXT("Win32k ETW references process invisible to client enumeration"),
        szDetails,
        DT_HIDDENPROCESS);
}

/*
* SkReportWin32kEtwHiddenThread
*
* Purpose:
*
* Reports a detected hidden thread referenced by Win32k ETW.
*
*/
VOID SkReportWin32kEtwHiddenThread(
    _In_ HANDLE UniqueThreadId,
    _In_opt_ LPCWSTR lpEventName,
    _In_opt_ LPCWSTR lpPropertyName,
    _In_ ULONG HitCount)
{
    WCHAR szDetails[MAX_TEXT_LENGTH];

    SkiIncreaseAnomalyCount();

    StringCchPrintf(szDetails,
        RTL_NUMBER_OF(szDetails),
        TEXT("TID: %llu, Event: %ws, Property: %ws, Hits: %lu"),
        (ULONG_PTR)UniqueThreadId,
        lpEventName ? lpEventName : TEXT("?"),
        lpPropertyName ? lpPropertyName : TEXT("?"),
        HitCount);

    supReportEvent(evtDetection,
        (LPWSTR)TEXT("Win32k ETW references thread not owned by any client-visible process"),
        szDetails,
        DT_HIDDENTHREAD);
}

/*
* SkPerformEtwTrace
*
* Purpose:
*
* Initialize and run ETW trace for detecting various wubbaboos through Win32k.
*
*/
BOOL SkPerformEtwTrace(
    _In_ PPROBE_CONTEXT Context
)
{
    UNREFERENCED_PARAMETER(Context);

    BOOL bResult = FALSE, bAbnormal = FALSE;
    ULONG i, oldAnomalyCount = SkiGetAnomalyCount();
    NTSTATUS status;
    HANDLE objectHandle;
    PVOID processList = NULL;
    SK_ETW_EVIDENCE_LIST etwPids, etwTids;
    OBJECT_ATTRIBUTES obja;
    CLIENT_ID cid;

    __try {

        RtlSecureZeroMemory(&etwPids, sizeof(etwPids));
        RtlSecureZeroMemory(&etwTids, sizeof(etwTids));

        //
        // Collect PIDs and TIDs observed by Win32k ETW during the
        // WM_NULL broadcast window.
        //
        if (!SkEtwpCollectWin32kEvidence(&etwPids, &etwTids)) {

            SkReportNtCallRIP(STATUS_UNSUCCESSFUL,
                (LPWSTR)TEXT("Cannot collect Win32k ETW events"),
                (LPWSTR)TEXT("SkEtwpCollectWin32kEvidence"),
                (LPWSTR)TEXT("Win32kGuiDiscoverySession"));

            __leave;
        }

        //
        // Enumerate the client-visible process tree after the ETW
        // collection. Any transient process (born and died inside the
        // collection window) will simply not be in the list, and will
        // be filtered out below via OpenProcess/OpenThread.
        //
        processList = supGetSystemInfo(SystemProcessInformation, NULL);
        if (processList == NULL) {

            SkReportNtCallRIP(STATUS_UNSUCCESSFUL,
                (LPWSTR)TEXT("Cannot query process list"),
                (LPWSTR)TEXT("NtQuerySystemInformation"),
                (LPWSTR)TEXT("SystemProcessInformation"));

            __leave;
        }

        //
        // PID cross-check.
        //
        for (i = 0; i < etwPids.Count; i++) {

            DWORD pid = etwPids.Items[i].EntityId;

            //
            // Visible to client enumeration - skip.
            //
            if (supProcessEntryByProcessId(UlongToHandle(pid), processList) != NULL)
                continue;

            //
            // Not in the visible list. Verify with the kernel.
            //
            InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
            cid.UniqueProcess = UlongToHandle(pid);
            cid.UniqueThread = NULL;

            status = NtOpenProcess(&objectHandle,
                PROCESS_QUERY_LIMITED_INFORMATION, &obja, &cid);

            if (NT_SUCCESS(status) && (objectHandle != NULL)) {
                //
                // Process exists, but NtQuerySystemInformation did not
                // list it. Report it.
                //
                SkReportWin32kEtwHiddenProcess(
                    UlongToHandle(pid),
                    etwPids.Items[i].EventName,
                    etwPids.Items[i].PropertyName,
                    etwPids.Items[i].HitCount);

                NtClose(objectHandle);
            }
            else {
                //
                // Protected / very-high-integrity process - still
                // suspicious because it is not enumerated.
                // Could be terminated between ETW session also, but since
                // we cannot sure (it maybe just filtered via hook)
                // report it.
                //
                SkReportNtCallRIP(status,
                    (LPWSTR)TEXT("Cannot open process"),
                    (LPWSTR)TEXT("SkPerformEtwTrace"),
                    (LPWSTR)TEXT("NtOpenProcess"));

            }
        }

        //
        // TID cross-check
        //
        for (i = 0; i < etwTids.Count; i++) {

            DWORD tid = etwTids.Items[i].EntityId;
            PSYSTEM_PROCESS_INFORMATION ownerEntry;

            if (supThreadToProcessEntry(processList, UlongToHandle(tid), &ownerEntry))
                continue;

            //
            // Orphan TID - verify with the kernel.
            //
            InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
            cid.UniqueProcess = NULL;
            cid.UniqueThread = UlongToHandle(tid);

            status = NtOpenThread(&objectHandle,
                THREAD_QUERY_LIMITED_INFORMATION, &obja, &cid);

            if (NT_SUCCESS(status) && (objectHandle != NULL)) {
                SkReportWin32kEtwHiddenThread(
                    UlongToHandle(tid),
                    etwTids.Items[i].EventName,
                    etwTids.Items[i].PropertyName,
                    etwTids.Items[i].HitCount);
                NtClose(objectHandle);
            }
            else {
                //
                // Same as with process case.
                //
                SkReportWin32kEtwHiddenThread(
                    UlongToHandle(tid),
                    etwTids.Items[i].EventName,
                    etwTids.Items[i].PropertyName,
                    etwTids.Items[i].HitCount);
            }
        }

        bResult = TRUE;
    }
    __finally {

        bAbnormal = AbnormalTermination();
        if (bAbnormal) {
            supReportEvent(evtError,
                DT_ETW_INTERNAL_ERROR,
                DT_UNEXPECTED_BEHAVIOUR,
                DT_EXCEPTION);
        }

        if (processList)
            supHeapFree(processList);

        SkEtwpFreeEvidenceList(&etwPids);
        SkEtwpFreeEvidenceList(&etwTids);
    }

    if (bAbnormal)
        return FALSE;

    return bResult && (SkiGetAnomalyCount() == oldAnomalyCount);
}
