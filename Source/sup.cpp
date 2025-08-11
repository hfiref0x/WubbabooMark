/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023 - 2025
*
*  TITLE:       SUP.CPP
*
*  VERSION:     1.10
*
*  DATE:        13 Jul 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

typedef union _GLOBAL_SID {
    SID sid;
    BYTE padding[SECURITY_MAX_SID_SIZE];
} GLOBAL_SID, * PGLOBAL_SID;

GLOBAL_SID gTrustedInstallerSid;
GLOBAL_SID gLocalSystemSid;
GLOBAL_SID gAdminsGroupSid;

typedef struct _SUP_KNOWNDLLS_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG NameHash;
    ULONG TypeHash;
} SUP_KNOWNDLLS_ENTRY, * PSUP_KNOWNDLLS_ENTRY;

#define DIRECTORY_SYSTEM32 L"\\systemroot\\system32"
#define DIRECTORY_KNOWNDLLS L"\\KnownDlls"
#define LDRP_MAX_MODULE_LOOP 10240

LIST_ENTRY gKnownDllsHead;

static const LPCSTR gPublisherAttributeObjId[] = {
    szOID_ORGANIZATION_NAME,
    szOID_LOCALITY_NAME,
    szOID_STATE_OR_PROVINCE_NAME,
    szOID_COUNTRY_NAME,
};

#define PUBLISHER_ATTR_CNT  RTL_NUMBER_OF(gPublisherAttributeObjId)

static const LPCWSTR gPublisherNameList[][PUBLISHER_ATTR_CNT] = {
    {
        L"Microsoft Corporation",
        L"Redmond",
        L"Washington",
        L"US"
    }
};
#define PUBLISHER_NAME_LIST_CNT  RTL_NUMBER_OF(gPublisherNameList)

#define IMAGELIST_COUNT 8

/*
* supWriteConfiguration
*
* Purpose:
*
* Write probe flags from registry if present.
*
*/
BOOL supWriteConfiguration(
    _In_ struct _PROBE_SETTINGS* Settings
)
{
    DWORD dwLastError = ERROR_SUCCESS;
    LSTATUS lResult;
    HKEY hKey = NULL;
    WCHAR szKey[MAX_PATH];

    StringCchPrintf(szKey, RTL_NUMBER_OF(szKey),
        TEXT("Software\\%ws"),
        PROGRAM_NAME);

    lResult = RegCreateKeyEx(HKEY_CURRENT_USER,
        szKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        NULL);

    if (ERROR_SUCCESS == lResult) {
        lResult = RegSetValueEx(hKey, TEXT("Settings"),
            0,
            REG_DWORD,
            (PBYTE)Settings,
            sizeof(PROBE_SETTINGS));

        if (lResult != ERROR_SUCCESS)
            dwLastError = GetLastError();

        RegCloseKey(hKey);
    }

    SetLastError(dwLastError);

    return lResult == ERROR_SUCCESS;
}

LSTATUS supxSetDefaultConfiguration(
    _In_ HKEY hKey,
    _In_ PROBE_SETTINGS* DefaultSettings
)
{
    LSTATUS lResult;

    lResult = RegSetValueEx(hKey, TEXT("Settings"),
        0,
        REG_DWORD,
        (PBYTE)DefaultSettings,
        sizeof(PROBE_SETTINGS));

    return lResult;
}

/*
* supReadConfiguration
*
* Purpose:
*
* Query probe flags from registry if present.
*
*/
BOOL supReadConfiguration(
    _Out_ struct _PROBE_SETTINGS* Settings
)
{
    DWORD dwLastError = ERROR_SUCCESS;
    LSTATUS lResult;
    HKEY hKey = NULL;
    WCHAR szKey[MAX_PATH];
    DWORD dwType = 0, dwSize, dwkeyDisposition = 0;
    PROBE_SETTINGS value;

    value.Flags = 0;
    Settings->Flags = 0xFFFFFFFF;

    StringCchPrintf(szKey, RTL_NUMBER_OF(szKey),
        TEXT("Software\\%ws"),
        PROGRAM_NAME);

    lResult = RegCreateKeyEx(HKEY_CURRENT_USER,
        szKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        NULL,
        &hKey,
        &dwkeyDisposition);

    if (ERROR_SUCCESS == lResult) {

        //
        // If there is something to read - do it, otherwise leave default values
        //
        if (REG_OPENED_EXISTING_KEY == dwkeyDisposition) {

            dwSize = sizeof(PROBE_SETTINGS);
            lResult = RegQueryValueEx(hKey,
                TEXT("Settings"),
                NULL,
                &dwType,
                (LPBYTE)&value,
                &dwSize);

            if (lResult == ERROR_SUCCESS) {
                if (dwType != REG_DWORD)
                    lResult = ERROR_BAD_CONFIGURATION;
                else
                    *Settings = value;

            }
            else {
                //
                // Value doesn't exist, set default.
                //
                lResult = supxSetDefaultConfiguration(hKey, Settings);
                if (lResult != ERROR_SUCCESS)
                    dwLastError = GetLastError();
            }
        }
        else {
            //
            // Key is created, first launch, set defaults.
            //
            lResult = supxSetDefaultConfiguration(hKey, Settings);
            if (lResult != ERROR_SUCCESS)
                dwLastError = GetLastError();

        }
        RegCloseKey(hKey);
    }

    SetLastError(dwLastError);
    return lResult == ERROR_SUCCESS;
}

/*
* supFindUnicodeStringSubString
*
* Purpose:
*
* Return offset to substring if found and ULLONG_MAX instead.
*
* Case Insensitive.
*
*/
SIZE_T supFindUnicodeStringSubString(
    _In_ PUNICODE_STRING String,
    _In_ PUNICODE_STRING SubString
)
{
    SIZE_T length1;
    SIZE_T length2;
    UNICODE_STRING string1;
    UNICODE_STRING string2;
    WCHAR c;
    SIZE_T i;

    if (SubString == NULL)
        return 0;

    length1 = String->Length / sizeof(WCHAR);
    length2 = SubString->Length / sizeof(WCHAR);

    if (length2 > length1)
        return ULLONG_MAX;

    if (length2 == 0)
        return 0;

    string1.Buffer = String->Buffer;
    string1.Length = SubString->Length - sizeof(WCHAR);
    string2.Buffer = SubString->Buffer;
    string2.Length = SubString->Length - sizeof(WCHAR);

    c = RtlUpcaseUnicodeChar(*string2.Buffer++);

    for (i = length1 - length2 + 1; i != 0; i--) {
        if (RtlUpcaseUnicodeChar(*string1.Buffer++) == c &&
            RtlEqualUnicodeString(&string1, &string2, TRUE))
        {
            return (ULONG_PTR)(string1.Buffer - String->Buffer - 1);
        }
    }

    return ULLONG_MAX;
}

/*
* supGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given SystemInformationClass.
*
* Caller must free buffer when it no longer needed.
*
*/
PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength
)
{
    PVOID buffer = NULL;
    ULONG bufferSize = PAGE_SIZE;
    NTSTATUS ntStatus;
    ULONG returnedLength = 0;

    if (ReturnLength)
        *ReturnLength = 0;

    buffer = supHeapAlloc((SIZE_T)bufferSize);
    if (buffer == NULL)
        return NULL;

    while ((ntStatus = NtQuerySystemInformation(
        SystemInformationClass,
        buffer,
        bufferSize,
        &returnedLength)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        supHeapFree(buffer);
        bufferSize <<= 1;

        if (bufferSize > NTQSI_MAX_BUFFER_LENGTH)
            return NULL;

        buffer = supHeapAlloc((SIZE_T)bufferSize);
    }

    if (ReturnLength)
        *ReturnLength = returnedLength;

    if (NT_SUCCESS(ntStatus)) {
        return buffer;
    }

    if (buffer)
        supHeapFree(buffer);

    return NULL;
}

/*
* supGetProcessInfoVariableSize
*
* Purpose:
*
* Returns buffer with system information by given ProcessInformationClass.
*
* Caller must free buffer when it no longer needed.
*
*/
PVOID supGetProcessInfoVariableSize(
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_opt_ PULONG ReturnLength
)
{
    PVOID buffer = NULL;
    ULONG bufferSize = PAGE_SIZE;
    NTSTATUS ntStatus;
    ULONG returnedLength = 0;

    if (ReturnLength)
        *ReturnLength = 0;

    buffer = supHeapAlloc((SIZE_T)bufferSize);
    if (buffer == NULL)
        return NULL;

    ntStatus = NtQueryInformationProcess(
        NtCurrentProcess(),
        ProcessInformationClass,
        buffer,
        bufferSize,
        &returnedLength);

    if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
        supHeapFree(buffer);
        bufferSize = returnedLength;
        buffer = supHeapAlloc((SIZE_T)bufferSize);

        ntStatus = NtQueryInformationProcess(
            NtCurrentProcess(),
            ProcessInformationClass,
            buffer,
            bufferSize,
            &returnedLength);
    }

    if (ReturnLength)
        *ReturnLength = returnedLength;

    if (NT_SUCCESS(ntStatus)) {
        return buffer;
    }

    if (buffer)
        supHeapFree(buffer);

    return NULL;
}

/*
* supRunAsAdmin
*
* Purpose:
*
* Restarts application requesting full admin rights.
*
*/
VOID supRunAsAdmin(
    VOID
)
{
    SHELLEXECUTEINFO shinfo;
    WCHAR szPath[MAX_PATH + 1];

    RtlSecureZeroMemory(&szPath, sizeof(szPath));
    if (GetModuleFileName(NULL, szPath, MAX_PATH)) {
        RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
        shinfo.cbSize = sizeof(shinfo);
        shinfo.lpVerb = TEXT("runas");
        shinfo.lpFile = szPath;
        shinfo.nShow = SW_SHOW;
        if (ShellExecuteEx(&shinfo)) {
            PostQuitMessage(0);
        }
    }
}

/*
* supLoadImageList
*
* Purpose:
*
* Create and load image list from icon resource type.
*
*/
HIMAGELIST supLoadImageList(
    _In_ HINSTANCE hInstance
)
{
    UINT       i;
    HIMAGELIST ImageList;
    HICON hIcon;

    ImageList = ImageList_Create(
        16,
        16,
        ILC_COLOR32 | ILC_MASK,
        IMAGELIST_COUNT,
        8);

    if (ImageList) {

        for (i = ICON_FIRST; i <= ICON_LAST; i++) {

            hIcon = (HICON)LoadImage(hInstance,
                MAKEINTRESOURCE(i),
                IMAGE_ICON,
                16,
                16,
                LR_DEFAULTCOLOR);

            if (hIcon) {
                ImageList_ReplaceIcon(ImageList, -1, hIcon);
                DestroyIcon(hIcon);
            }
        }

    }

    return ImageList;
}

/*
* supStatusBarSetText
*
* Purpose:
*
* Display status in status bar part.
*
*/
VOID supStatusBarSetText(
    _In_ HWND StatusBar,
    _In_ WPARAM Index,
    _In_ LPCWSTR Text
)
{
    SendMessage(StatusBar, SB_SETTEXT, Index, (LPARAM)Text);
}

/*
* supSetListViewSettings
*
* Purpose:
*
* Set listview imagelist, style flags and theme.
*
*/
VOID supSetListViewSettings(
    _In_ HWND hwndLV,
    _In_ DWORD dwExtendedStyle,
    _In_ BOOL fSetTheme,
    _In_opt_ HIMAGELIST hImageList,
    _In_ INT iImageList
)
{
    DWORD dwFlags = dwExtendedStyle;

    ListView_SetExtendedListViewStyle(hwndLV, dwFlags);

    if (hImageList) {
        ListView_SetImageList(hwndLV, hImageList, iImageList);
    }

    if (fSetTheme) {
        SetWindowTheme(hwndLV, TEXT("Explorer"), NULL);
    }
}

/*
* supAddListViewColumn
*
* Purpose:
*
* Wrapper for ListView_InsertColumn.
*
*/
INT supAddListViewColumn(
    _In_ HWND ListViewHwnd,
    _In_ INT ColumnIndex,
    _In_ INT SubItemIndex,
    _In_ INT OrderIndex,
    _In_ INT Format,
    _In_ LPWSTR Text,
    _In_ INT Width
)
{
    LVCOLUMN column;

    column.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER;
    column.fmt = Format;
    column.cx = Width;
    column.pszText = Text;
    column.iSubItem = SubItemIndex;
    column.iOrder = OrderIndex;

    return ListView_InsertColumn(ListViewHwnd, ColumnIndex, &column);
}

/*
* supAddLVColumnsFromArray
*
* Purpose:
*
* Add columns from array to the listview.
*
*/
ULONG supAddLVColumnsFromArray(
    _In_ HWND ListView,
    _In_ PLVCOLUMNS_DATA ColumnsData,
    _In_ ULONG NumberOfColumns
)
{
    ULONG iColumn;

    for (iColumn = 0; iColumn < NumberOfColumns; iColumn++) {

        if (-1 == supAddListViewColumn(ListView,
            iColumn,
            iColumn,
            iColumn,
            ColumnsData[iColumn].Format,
            ColumnsData[iColumn].Name,
            ColumnsData[iColumn].Width))
        {
            break;
        }
    }

    return iColumn;
}

/*
* supReportEventEx
*
* Purpose:
*
* Add item to the main window listview, filter duplicate if requested.
*
*/
VOID supReportEventEx(
    _In_ DR_EVENT_TYPE EventType,
    _In_ LPWSTR lpEvent,
    _In_opt_ LPWSTR lpDescription,
    _In_opt_ LPWSTR lpAnomalyType,
    _In_ ULONG_PTR lParam,
    _In_ BOOLEAN fCheckDuplicate
)
{
    INT iImage = IDI_ICON_CHECK_PASSED;
    INT lvItemIndex;
    LVITEM lvItem;

    if (fCheckDuplicate) {

        LVFINDINFO findInfo;

        RtlSecureZeroMemory(&findInfo, sizeof(findInfo));

        findInfo.flags = LVFI_PARAM;
        findInfo.lParam = lParam;

        if (-1 != ListView_FindItem(hwndList, 0, &findInfo))
            return;
    }

    switch (EventType) {

    case evtError:
        iImage = IDI_ICON_CHECK_FAILED;
        break;

    case evtWarning:
        iImage = IDI_ICON_CHECK_WARNING;
        break;

    case evtDetection:
        iImage = IDI_ICON_DETECTION;
        break;

    default:
        break;
    }

    RtlSecureZeroMemory(&lvItem, sizeof(lvItem));

    lvItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
    lvItem.pszText = lpEvent;
    lvItem.iImage = iImage - ICON_FIRST;
    lvItem.iItem = MAXINT;
    lvItem.lParam = lParam;
    lvItemIndex = ListView_InsertItem(hwndList, &lvItem);

    lvItem.mask = LVIF_TEXT;
    lvItem.iSubItem = 1;
    if (lpDescription) {
        lvItem.pszText = lpDescription;
    }
    else {
        lvItem.pszText = (LPWSTR)TEXT("");
    }
    lvItem.iItem = lvItemIndex;
    ListView_SetItem(hwndList, &lvItem);

    lvItem.mask = LVIF_TEXT;
    lvItem.iSubItem = 2;
    if (lpAnomalyType) {
        lvItem.pszText = lpAnomalyType;
    }
    else {
        lvItem.pszText = (LPWSTR)TEXT("");
    }
    lvItem.iItem = lvItemIndex;
    ListView_SetItem(hwndList, &lvItem);
}

/*
* supReportEvent
*
* Purpose:
*
* Add item to the main window listview.
*
*/
VOID supReportEvent(
    _In_ DR_EVENT_TYPE EventType,
    _In_ LPWSTR lpEvent,
    _In_opt_ LPWSTR lpDescription,
    _In_opt_ LPWSTR lpAnomalyType
)
{
    supReportEventEx(EventType,
        lpEvent,
        lpDescription,
        lpAnomalyType,
        0,
        FALSE);
}

/*
* supGetCurrentProcessToken
*
* Purpose:
*
* Return current process token value with TOKEN_QUERY access right.
*
*/
HANDLE supGetCurrentProcessToken(
    VOID)
{
    HANDLE tokenHandle = NULL;

    if (NT_SUCCESS(NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &tokenHandle)))
    {
        return tokenHandle;
    }
    return NULL;
}

/*
* supUserIsFullAdmin
*
* Purpose:
*
* Tests if the current user is admin with full access token.
*
*/
BOOL supUserIsFullAdmin(
    VOID
)
{
    BOOL bResult = FALSE;
    HANDLE hToken = NULL;
    NTSTATUS status;
    DWORD i, Attributes;
    ULONG ReturnLength = 0;

    PTOKEN_GROUPS pTkGroups;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = NULL;

    status = NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    if (!NT_SUCCESS(status))
        return bResult;

    do {
        if (!NT_SUCCESS(RtlAllocateAndInitializeSid(
            &ntAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &adminGroup)))
        {
            break;
        }

        status = NtQueryInformationToken(hToken, TokenGroups, NULL, 0, &ReturnLength);
        if (status != STATUS_BUFFER_TOO_SMALL)
            break;

        pTkGroups = (PTOKEN_GROUPS)supHeapAlloc((SIZE_T)ReturnLength);
        if (pTkGroups == NULL)
            break;

        status = NtQueryInformationToken(hToken, TokenGroups, pTkGroups, ReturnLength, &ReturnLength);
        if (NT_SUCCESS(status)) {
            if (pTkGroups->GroupCount > 0)
                for (i = 0; i < pTkGroups->GroupCount; i++) {
                    Attributes = pTkGroups->Groups[i].Attributes;
                    if (RtlEqualSid(adminGroup, pTkGroups->Groups[i].Sid))
                        if (
                            (Attributes & SE_GROUP_ENABLED) &&
                            (!(Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
                            )
                        {
                            bResult = TRUE;
                            break;
                        }
                }
        }
        supHeapFree(pTkGroups);

    } while (FALSE);

    if (adminGroup != NULL) {
        RtlFreeSid(adminGroup);
    }

    NtClose(hToken);
    return bResult;
}

/*
* supxGetShellViewForDesktop
*
* Purpose:
*
* Use the shell view for the desktop using the shell windows automation to find the
* desktop web browser and then grabs its view.
*
* N.B. Taken entirely from Windows SDK sample.
*
*/
HRESULT supxGetShellViewForDesktop(
    REFIID riid,
    void** ppv
)
{
    IShellWindows* psw;
    HRESULT hr;
    HWND hwnd;
    IDispatch* pdisp;
    IShellBrowser* psb;
    VARIANT vtEmpty;
    IShellView* psv;

    *ppv = NULL;

    hr = CoCreateInstance(CLSID_ShellWindows, NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&psw));
    if (SUCCEEDED(hr))
    {
        VariantInit(&vtEmpty);

        if (S_OK == psw->FindWindowSW(&vtEmpty, &vtEmpty, SWC_DESKTOP, (long*)(LONG_PTR)&hwnd, SWFO_NEEDDISPATCH, &pdisp))
        {
            hr = IUnknown_QueryService(pdisp, SID_STopLevelBrowser, IID_PPV_ARGS(&psb));
            if (SUCCEEDED(hr))
            {

                hr = psb->QueryActiveShellView(&psv);
                if (SUCCEEDED(hr))
                {
                    hr = psv->QueryInterface(riid, ppv);
                    psv->Release();
                }
                psb->Release();
            }
            pdisp->Release();
        }
        else
        {
            hr = E_FAIL;
        }
        psw->Release();
    }

    return hr;
}

/*
* supxGetShellDispatchFromView
*
* Purpose:
*
* From a shell view object gets its automation interface and from that gets the shell
* application object that implements IShellDispatch2 and related interfaces.
*
* N.B. Taken entirely from Windows SDK sample.
*
*/
HRESULT supxGetShellDispatchFromView(IShellView* psv, REFIID riid, void** ppv)
{
    HRESULT hr;
    IDispatch* pdispBackground;
    IShellFolderViewDual* psfvd;
    IDispatch* pdisp;

    *ppv = NULL;

    hr = psv->GetItemObject(SVGIO_BACKGROUND, IID_PPV_ARGS(&pdispBackground));
    if (SUCCEEDED(hr))
    {
        hr = pdispBackground->QueryInterface(IID_PPV_ARGS(&psfvd));
        if (SUCCEEDED(hr))
        {
            hr = psfvd->get_Application(&pdisp);
            if (SUCCEEDED(hr))
            {
                hr = pdisp->QueryInterface(riid, ppv);
                pdisp->Release();
            }
            psfvd->Release();
        }
        pdispBackground->Release();
    }

    return hr;
}

/*
* supShellExecInExplorerProcess
*
* Purpose:
*
* Run ShellExecute from Windows Explorer process through shell interfaces
* making it run with IL of Windows Explorer and not current process.
*
*/
HRESULT supShellExecInExplorerProcess(
    _In_ PCWSTR pszFile,
    _In_opt_ PCWSTR pszArguments
)
{
    HRESULT hr, hr_init;
    IShellView* psv;
    IShellDispatch2* psd;
    BSTR bstrFile, bstrArgs = NULL;
    VARIANT vtEmpty, vtArgs;

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    hr = supxGetShellViewForDesktop(IID_PPV_ARGS(&psv));
    if (SUCCEEDED(hr))
    {
        hr = supxGetShellDispatchFromView(psv, IID_PPV_ARGS(&psd));
        if (SUCCEEDED(hr))
        {
            bstrFile = SysAllocString(pszFile);
            hr = bstrFile ? S_OK : E_OUTOFMEMORY;
            if (SUCCEEDED(hr))
            {
                VariantInit(&vtArgs);
                VariantInit(&vtEmpty);

                if (pszArguments) {
                    bstrArgs = SysAllocString(pszArguments);
                    hr = bstrArgs ? S_OK : E_OUTOFMEMORY;

                    if (SUCCEEDED(hr)) {
                        vtArgs.vt = VT_BSTR;
                        vtArgs.bstrVal = bstrArgs;

                        hr = psd->ShellExecuteW(bstrFile,
                            vtArgs, vtEmpty, vtEmpty, vtEmpty);

                        SysFreeString(bstrFile);
                    }
                }
                else {

                    hr = psd->ShellExecuteW(bstrFile,
                        vtEmpty, vtEmpty, vtEmpty, vtEmpty);

                }

            }
            psd->Release();
        }
        psv->Release();
    }
    if (SUCCEEDED(hr_init)) CoUninitialize();
    return hr;
}

/*
* supSyscallAddressFromServiceEntry
*
* Purpose:
*
* Retrieve syscall instruction address from the given service entry.
*
*/
ULONG_PTR supSyscallAddressFromServiceEntry(
    _In_ PVOID ModuleBase,
    _In_ LPCSTR ServiceEntryName
)
{
    PBYTE ptrCode;
    hde64s hs;

    ptrCode = (PBYTE)supLdrGetProcAddressEx(ModuleBase, ServiceEntryName);

    if (ptrCode) {

        ULONG i = 0, maxLen = 32;

        do {

            hde64_disasm(RtlOffsetToPointer(ptrCode, i), &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 2) {

                if (hs.opcode == 0x0f &&
                    hs.opcode2 == 0x05 &&
                    hs.flags == 0)
                {
                    return (ULONG_PTR)RtlOffsetToPointer(ptrCode, i);
                }

            }

            i += hs.len;

        } while (i < maxLen);

    }

    return 0;
}

/*
* supxExtractSyscallNumberFromImage
*
* Purpose:
*
* Retrieve syscall service number value from function code.
*
*/
ULONG supxExtractSyscallNumberFromImage(
    _In_ PVOID ImageBase,
    _In_ LPCSTR FunctionName
)
{
    PBYTE ptrCode;

    ptrCode = (PBYTE)supLdrGetProcAddressEx(ImageBase, FunctionName);

    if (ptrCode) {

        if (ptrCode[0] == 0x4C &&
            ptrCode[1] == 0x8B &&
            (ptrCode[2] & 0xC0) == 0xC0)
        {
            return *(ULONG*)((BYTE*)ptrCode + 4);
        }

    }

    return INVALID_SYSCALL_ID;
}

/*
* supxExtractSyscallNumberFromImage2
*
* Purpose:
*
* Retrieve syscall service number value by address sorting.
*
*/
ULONG supxExtractSyscallNumberFromImage2(
    _In_ PVOID ImageBase,
    _In_ BOOL IsNtDll,
    _In_ LPCSTR FunctionName
)
{
    EXPORT_NODE* pExportTable;
    EXPORT_NODE* newHead = NULL, * node, * current;
    ULONG ulSSN, ulResult = INVALID_SYSCALL_ID;
    ULONG syscallBase = 0;

    if (ImageBase == NULL)
        return INVALID_SYSCALL_ID;

    PVOID pvEnumHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);

    if (pvEnumHeap) {

        if (supEnumServiceExports((HANDLE)pvEnumHeap,
            ImageBase,
            IsNtDll,
            &pExportTable))
        {
            while (pExportTable) {

                node = pExportTable;
                pExportTable = pExportTable->Next;

                if (newHead == NULL || node->Address < newHead->Address) {
                    node->Next = newHead;
                    newHead = node;
                }
                else {
                    current = newHead;
                    while (current->Next && !(node->Address < current->Next->Address))
                        current = current->Next;

                    node->Next = current->Next;
                    current->Next = node;
                }
            }

            pExportTable = newHead;
            ulSSN = 0;

            if (!IsNtDll)
                syscallBase = W32K_TABLE_INDEX_BASE;

            while (pExportTable) {

                if (_strcmpi_a(pExportTable->Name, FunctionName) == 0) {
                    ulResult = ulSSN + syscallBase;
                    break;
                }

                pExportTable = pExportTable->Next;
                ulSSN += 1;
            }

        }

        RtlDestroyHeap(pvEnumHeap);
    }

    return ulResult;
}

/*
* supxExtractSyscallNumberFromImage3
*
* Purpose:
*
* Retrieve syscall service number value by runtime table walking.
*
*/
ULONG supxExtractSyscallNumberFromImage3(
    _In_ PVOID ImageBase,
    _In_ BOOL IsNtDll,
    _In_ LPCSTR FunctionName
)
{
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PIMAGE_RUNTIME_FUNCTION_ENTRY ImageRuntimeEntry = NULL;
    PULONG NameTableBase;
    PULONG AddressTableBase;
    PUSHORT NameOrdinalTableBase;
    PCHAR exportName;
    ULONG i, j, syscallNumber, syscallBase;
    DWORD RVA;
    USHORT servicePrefix;

    union {
        PIMAGE_NT_HEADERS64 nt64;
        PIMAGE_NT_HEADERS32 nt32;
        PIMAGE_NT_HEADERS nt;
    } NtHeaders;

    if (!NT_SUCCESS(RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK,
        ImageBase, 0, &NtHeaders.nt)))
    {
        return INVALID_SYSCALL_ID;
    }

    if (NtHeaders.nt == NULL) {
        return INVALID_SYSCALL_ID;
    }

    if (NtHeaders.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {

        RVA = NtHeaders.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (RVA == 0)
            return INVALID_SYSCALL_ID;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(ImageBase, RVA);

        RVA = NtHeaders.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        if (RVA == 0)
            return INVALID_SYSCALL_ID;

        ImageRuntimeEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)RtlOffsetToPointer(ImageBase, RVA);

    }
    else if (NtHeaders.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {

        RVA = NtHeaders.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (RVA == 0)
            return INVALID_SYSCALL_ID;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(ImageBase, RVA);

        RVA = NtHeaders.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        if (RVA == 0)
            return INVALID_SYSCALL_ID;

        ImageRuntimeEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)RtlOffsetToPointer(ImageBase, RVA);

    }
    else
    {
        return INVALID_SYSCALL_ID;
    }

    if (ExportDirectory == NULL ||
        ImageRuntimeEntry == NULL)
    {
        return INVALID_SYSCALL_ID;
    }

    syscallNumber = 0;
    if (IsNtDll) {
        servicePrefix = 'wZ';
        syscallBase = 0;
    }
    else {
        servicePrefix = 'tN';
        syscallBase = W32K_TABLE_INDEX_BASE;
    }

    NameTableBase = (PULONG)RtlOffsetToPointer(ImageBase, (ULONG)ExportDirectory->AddressOfNames);
    NameOrdinalTableBase = (PUSHORT)RtlOffsetToPointer(ImageBase, (ULONG)ExportDirectory->AddressOfNameOrdinals);
    AddressTableBase = (PULONG)RtlOffsetToPointer(ImageBase, (ULONG)ExportDirectory->AddressOfFunctions);

    for (i = 0; ImageRuntimeEntry[i].BeginAddress; i++) {
        for (j = 0; j < ExportDirectory->NumberOfFunctions; j++) {

            if (AddressTableBase[NameOrdinalTableBase[j]] == ImageRuntimeEntry[i].BeginAddress) {

                exportName = (PCHAR)RtlOffsetToPointer(ImageBase, NameTableBase[j]);

                if (_strcmpi_a(FunctionName, exportName) == 0) {
                    return syscallNumber + syscallBase;
                }

                if (*(USHORT*)exportName == servicePrefix)
                    syscallNumber++;
            }
        }
    }

    return INVALID_SYSCALL_ID;
}

enum {
    LockFree = 0,
    LockTaken = 1
};

volatile LONG SkiCallInProgress = LockTaken;
volatile LONG SkiCallWaitForMain = LockTaken;

ULONG supxSSNProbeThread(
    _In_ PFEFN Routine)
{
    Routine();

    InterlockedExchange(&SkiCallInProgress, LockFree);

    while (LockTaken == _InterlockedCompareExchange(&SkiCallWaitForMain,
        LockTaken,
        LockFree));

    return 0;
}

/*
* supExtractSyscallNumberFromRoutine
*
* Purpose:
*
* Retrieve syscall service number value by thread information.
*
*/
ULONG supExtractSyscallNumberFromRoutine(
    _In_ PFEFN Routine)
{
    ULONG syscallId = INVALID_SYSCALL_ID;
    HANDLE threadHandle;
    NTSTATUS ntStatus;
    DWORD threadId, dummy;
    THREAD_LAST_SYSCALL_INFORMATION lsi;

    threadHandle = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)supxSSNProbeThread,
        (PVOID)Routine, 0, &threadId);

    if (threadHandle) {

        while (LockTaken == _InterlockedCompareExchange(
            &SkiCallInProgress,
            LockTaken,
            LockFree));

        ntStatus = NtSuspendThread(threadHandle, &dummy);
        if (NT_SUCCESS(ntStatus)) {

            SwitchToThread();

            ULONG retryCount = 100;

            do {

                ntStatus = NtQueryInformationThread(threadHandle, ThreadLastSystemCall,
                    &lsi, sizeof(lsi), &dummy);
                if (NT_SUCCESS(ntStatus)) {
                    syscallId = lsi.SystemCallNumber;
                    break;
                }

                Sleep(10);

            } while (--retryCount);

            InterlockedExchange(&SkiCallWaitForMain, LockFree);
            NtResumeThread(threadHandle, &dummy);
            if (WaitForSingleObject(threadHandle, 1000) == WAIT_TIMEOUT)
                NtTerminateThread(threadHandle, STATUS_ABANDONED_WAIT_0);
        }
        else {
            NtTerminateThread(threadHandle, ntStatus);
        }

        CloseHandle(threadHandle);
    }

    return syscallId;
}

/*
* supExtractSSN
*
* Purpose:
*
* Extract syscall system number by various methods.
*
*/
ULONG supExtractSSN(
    _In_ SSN_EXTRACT_METHOD Method,
    _In_ PVOID ImageBase,
    _In_ BOOL IsNtDll,
    _In_ LPCSTR FunctionName
)
{
    PFEFN pfnRoutine;

    if (ImageBase == NULL)
        return INVALID_SYSCALL_ID;

    switch (Method) {

    case SsnInstructionScan:
        return supxExtractSyscallNumberFromImage(ImageBase,
            FunctionName);

    case SsnSortedScan:
        return supxExtractSyscallNumberFromImage2(ImageBase,
            IsNtDll,
            FunctionName);

    case SsnRuntimeScan:
        return supxExtractSyscallNumberFromImage3(ImageBase,
            IsNtDll,
            FunctionName);

    case SsnThreadInformation:
        if (IsNtDll) {
            pfnRoutine = (PFEFN)supGetNtStubByName(FunctionName);
            if (pfnRoutine) {
                return supExtractSyscallNumberFromRoutine(pfnRoutine);
            }
        }
        break;
    }

    return INVALID_SYSCALL_ID;
}

/*
* supLdrGetProcAddressEx
*
* Purpose:
*
* Simplified GetProcAddress reimplementation.
*
*/
LPVOID supLdrGetProcAddressEx(
    _In_ LPVOID ImageBase,
    _In_ LPCSTR RoutineName
)
{
    USHORT OrdinalIndex;
    LONG Result;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PULONG NameTableBase, FunctionTableBase;
    PUSHORT NameOrdinalTableBase;
    PCHAR CurrentName;
    ULONG High, Low, Middle = 0;
    ULONG ExportDirRVA, ExportDirSize;
    ULONG FunctionRVA;

    union {
        PIMAGE_NT_HEADERS64 nt64;
        PIMAGE_NT_HEADERS32 nt32;
        PIMAGE_NT_HEADERS nt;
    } NtHeaders;

    if (ImageBase == NULL || RoutineName == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    NtHeaders.nt = RtlImageNtHeader(ImageBase);
    if (NtHeaders.nt == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    if (NtHeaders.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        ExportDirRVA = NtHeaders.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ExportDirSize = NtHeaders.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    else if (NtHeaders.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        ExportDirRVA = NtHeaders.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ExportDirSize = NtHeaders.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    else {
        SetLastError(ERROR_EXE_MACHINE_TYPE_MISMATCH);
        return NULL;
    }

    if (ExportDirRVA == 0 || ExportDirSize == 0) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer((ULONG_PTR)ImageBase, ExportDirRVA);
    NameTableBase = (PULONG)RtlOffsetToPointer(ImageBase, (ULONG)ExportDirectory->AddressOfNames);
    NameOrdinalTableBase = (PUSHORT)RtlOffsetToPointer(ImageBase, (ULONG)ExportDirectory->AddressOfNameOrdinals);
    FunctionTableBase = (PULONG)((ULONG_PTR)ImageBase + ExportDirectory->AddressOfFunctions);

    if (ExportDirectory->NumberOfNames == 0) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    Low = 0;
    High = ExportDirectory->NumberOfNames - 1;

    while (Low <= High) {
        Middle = Low + (High - Low) / 2;
        CurrentName = (PCHAR)RtlOffsetToPointer((ULONG_PTR)ImageBase, NameTableBase[Middle]);
        Result = _strcmp_a(RoutineName, CurrentName);
        if (Result == 0) {
            OrdinalIndex = NameOrdinalTableBase[Middle];
            if (OrdinalIndex >= ExportDirectory->NumberOfFunctions) {
                SetLastError(ERROR_PROC_NOT_FOUND);
                return NULL;
            }
            FunctionRVA = FunctionTableBase[OrdinalIndex];
            if (FunctionRVA == 0) {
                SetLastError(ERROR_PROC_NOT_FOUND);
                return NULL;
            }
            return (LPVOID)RtlOffsetToPointer((ULONG_PTR)ImageBase, FunctionRVA);
        }
        if (Result < 0) {
            if (Middle == 0) break;
            High = Middle - 1;
        }
        else {
            Low = Middle + 1;
        }

    }

    SetLastError(ERROR_PROC_NOT_FOUND);
    return NULL;
}

/*
* supEnumServiceExports
*
* Purpose:
*
* Walk dll exports and collect every service entry.
*
*/
ULONG supEnumServiceExports(
    _In_ HANDLE HeapHandle,
    _In_ LPVOID ImageBase,
    _In_ BOOL IsNtDll,
    _Out_ EXPORT_NODE** ExportTable
)
{
    ULONG i, j, numberOfEntries;
    ULONG_PTR fnptr;

    LPCSTR lpfnName;

    DWORD numberOfRvaAndSizes;
    ULONG_PTR exportRva, expSize;
    PIMAGE_EXPORT_DIRECTORY	exportDirectory;
    PDWORD fnTable, nameTable;
    PWORD nameOrdTable;

    USHORT servicePrefix;

    EXPORT_NODE* pTableEntry;

    union {
        PIMAGE_NT_HEADERS64 nt64;
        PIMAGE_NT_HEADERS32 nt32;
        PIMAGE_NT_HEADERS nt;
    } NtHeaders;

    *ExportTable = NULL;

    SetLastError(ERROR_SUCCESS);

    if (!NT_SUCCESS(RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK,
        ImageBase, 0, &NtHeaders.nt)))
    {
        return NULL;
    }

    if (NtHeaders.nt == NULL)
        return NULL;

    if (NtHeaders.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        numberOfRvaAndSizes = NtHeaders.nt64->OptionalHeader.NumberOfRvaAndSizes;
        exportRva = NtHeaders.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        expSize = NtHeaders.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    else if (NtHeaders.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        numberOfRvaAndSizes = NtHeaders.nt32->OptionalHeader.NumberOfRvaAndSizes;
        exportRva = NtHeaders.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        expSize = NtHeaders.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    else {
        SetLastError(ERROR_UNSUPPORTED_TYPE);
        return NULL;
    }

    if (numberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT || exportRva == 0) {
        SetLastError(ERROR_UNSUPPORTED_TYPE);
        return NULL;
    }

    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(ImageBase, exportRva);
    fnTable = (PDWORD)RtlOffsetToPointer(ImageBase, exportDirectory->AddressOfFunctions);
    nameTable = (PDWORD)RtlOffsetToPointer(ImageBase, exportDirectory->AddressOfNames);
    nameOrdTable = (PWORD)RtlOffsetToPointer(ImageBase, exportDirectory->AddressOfNameOrdinals);

    numberOfEntries = 0;

    if (IsNtDll)
        servicePrefix = 'wZ';
    else
        servicePrefix = 'tN';

    for (i = 0; i < exportDirectory->NumberOfFunctions; ++i)
    {
        fnptr = (ULONG_PTR)ImageBase + fnTable[i];

        for (j = 0; j < exportDirectory->NumberOfNames; ++j)
        {
            if (nameOrdTable[j] == i)
            {
                lpfnName = (LPCSTR)RtlOffsetToPointer(ImageBase, nameTable[j]);
                if (*(USHORT*)lpfnName == servicePrefix) {

                    pTableEntry = (EXPORT_NODE*)RtlAllocateHeap(HeapHandle, HEAP_ZERO_MEMORY, sizeof(EXPORT_NODE));
                    if (pTableEntry) {

                        _strncpy_a((char*)&pTableEntry->Name,
                            sizeof(pTableEntry->Name),
                            lpfnName,
                            sizeof(pTableEntry->Name));

                        //
                        // Hack for consistency.
                        //
                        if (IsNtDll) {
                            pTableEntry->Name[0] = L'N';
                            pTableEntry->Name[1] = L't';
                        }

                        pTableEntry->Address = (ULONG_PTR)RtlOffsetToPointer(ImageBase, fnTable[i]);
                        ++numberOfEntries;

                        *ExportTable = pTableEntry;
                        ExportTable = &pTableEntry->Next;
                    }

                    break;
                }

            }
        }

    }

    return numberOfEntries;
}

/*
* supLdrFindImageByAddressEx
*
* Purpose:
*
* Find base address for the given address value.
*
*/
PVOID supLdrFindImageByAddressEx(
    _In_ BOOL LockLoader,
    _In_opt_ PVOID AddressValue,
    _Out_ PVOID* ImageBase
)
{
    ULONG_PTR imageBounds;

    PLDR_DATA_TABLE_ENTRY ldrTableEntry;
    PLIST_ENTRY listHead;
    PLIST_ENTRY nextEntry;

    PIMAGE_NT_HEADERS NtHeaders;

    PVOID foundBase = NULL, pvImageBase = NULL;

    PPEB currentPeb = NtCurrentPeb();

    MEMORY_BASIC_INFORMATION mi;

    ULONG lockDisposition = LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID;
    PVOID lockCookie = NULL;

    NTSTATUS ntStatus;

    *ImageBase = NULL;

    if (LockLoader) {
        ntStatus = LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY,
            &lockDisposition, &lockCookie);

        if (!NT_SUCCESS(ntStatus))
            return NULL;

        //
        // Loader lock failed. Query virtual memory.
        //

        if (lockDisposition == LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_NOT_ACQUIRED) {

            ntStatus = NtQueryVirtualMemory(
                NtCurrentProcess(),
                AddressValue,
                MemoryBasicInformation,
                &mi,
                sizeof(MEMORY_BASIC_INFORMATION),
                NULL);

            if (!NT_SUCCESS(ntStatus)) {
                mi.AllocationBase = NULL;
            }
            else {
                if (mi.Type == MEM_IMAGE) {
                    *ImageBase = mi.AllocationBase;
                }
                else {
                    mi.AllocationBase = NULL;;
                }
            }
            return mi.AllocationBase;
        }

    }

    //
    // Walk PEB.
    //

    __try {

        ULONG cLoops = 0;

        if (currentPeb->Ldr != NULL) {
            listHead = &currentPeb->Ldr->InLoadOrderModuleList;
            nextEntry = listHead->Flink;
            if (nextEntry != NULL) {
                while (nextEntry != listHead && cLoops < LDRP_MAX_MODULE_LOOP) {

                    ldrTableEntry = CONTAINING_RECORD(nextEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                    pvImageBase = ldrTableEntry->DllBase;

                    if (NT_SUCCESS(RtlImageNtHeaderEx(0, pvImageBase, ldrTableEntry->SizeOfImage, &NtHeaders))) {
                        imageBounds = (ULONG_PTR)RtlOffsetToPointer(pvImageBase, NtHeaders->OptionalHeader.SizeOfImage);
                        if (IN_REGION(AddressValue, pvImageBase, NtHeaders->OptionalHeader.SizeOfImage)) {
                            foundBase = pvImageBase;
                            break;
                        }

                    }

                    nextEntry = nextEntry->Flink;
                    cLoops += 1;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        foundBase = NULL;
    }

    if (LockLoader) {
        LdrUnlockLoaderLock(0, lockCookie);
    }

    *ImageBase = foundBase;
    return foundBase;
}

/*
* supLdrFindImageByAddress
*
* Purpose:
*
* Find base address for the given address value.
*
*/
PVOID supLdrFindImageByAddress(
    _In_opt_ PVOID AddressValue,
    _Out_ PVOID* ImageBase
)
{
    return supLdrFindImageByAddressEx(TRUE, AddressValue, ImageBase);
}

/*
* supUnhandledExceptionFilter
*
* Purpose:
*
* Say something before crash.
*
*/
ULONG NTAPI supUnhandledExceptionFilter(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
    DbgPrint((PCH)"[SK] Unhandled exception 0x%x at address %p\n",
        ExceptionInfo->ExceptionRecord->ExceptionCode,
        ExceptionInfo->ExceptionRecord->ExceptionAddress);

    return EXCEPTION_EXECUTE_HANDLER;
}

/*
* supGetObjectTypesInfo
*
* Purpose:
*
* Returns buffer with system types information.
*
* Returned buffer must be freed with supHeapFree after usage.
*
*/
NTSTATUS supGetObjectTypesInfo(
    _Out_ PULONG ReturnLength,
    _Out_ PVOID* Buffer
)
{
    PVOID buffer = NULL;
    ULONG bufferSize = 1024 * 16;
    NTSTATUS ntStatus;
    ULONG returnedLength = 0;

    *ReturnLength = 0;
    *Buffer = NULL;

    buffer = supHeapAlloc((SIZE_T)bufferSize);
    if (buffer == NULL)
        return NULL;

    while ((ntStatus = NtQueryObject(
        NULL,
        ObjectTypesInformation,
        buffer,
        bufferSize,
        &returnedLength)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        supHeapFree(buffer);
        bufferSize <<= 1;

        if (bufferSize > (16 * 1024 * 1024))
            return NULL;

        buffer = supHeapAlloc((SIZE_T)bufferSize);
    }

    if (NT_SUCCESS(ntStatus)) {
        *ReturnLength = returnedLength;
        *Buffer = buffer;
        return ntStatus;
    }

    if (buffer) {
        supHeapFree(buffer);
    }

    return ntStatus;
}

/*
* supGetImageBaseUnsafe
*
* Purpose:
*
* Find base address for the given address value through brute-force.
*
*/
PVOID supGetImageBaseUnsafe(
    _In_ ULONG_PTR AddressValue
)
{
    PVOID baseAddress = NULL;
    ULONG returnLength = 0;
    SYSTEM_BASIC_INFORMATION sbi;
    ULONG_PTR probeAddress, allocationGranularity;

    if (NT_SUCCESS(NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), &returnLength))) {

        allocationGranularity = sbi.AllocationGranularity;

        __try {

            probeAddress = AddressValue & ~(allocationGranularity - 1);

            do {

                if ((((IMAGE_DOS_HEADER*)probeAddress)->e_magic == IMAGE_DOS_SIGNATURE) &&
                    (((IMAGE_NT_HEADERS*)RtlOffsetToPointer(probeAddress,
                        ((IMAGE_DOS_HEADER*)probeAddress)->e_lfanew))->Signature == IMAGE_NT_SIGNATURE))
                {
                    return (PVOID)probeAddress;
                }

                probeAddress -= allocationGranularity;
            } while (TRUE);

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return NULL;
        }
    }
    return baseAddress;
}

/*
* supVirtualAlloc
*
* Purpose:
*
* Wrapper for NtAllocateVirtualMemory.
*
*/
PVOID supVirtualAlloc(
    _In_ SIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect)
{
    NTSTATUS ntStatus;
    PVOID bufferPtr = NULL;
    SIZE_T bufferSize;

    bufferSize = Size;
    ntStatus = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &bufferPtr,
        0,
        &bufferSize,
        AllocationType,
        Protect);

    if (NT_SUCCESS(ntStatus)) {
        return bufferPtr;
    }

    RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    return NULL;
}

/*
* supVirtualFree
*
* Purpose:
*
* Wrapper for NtFreeVirtualMemory.
*
*/
BOOL supVirtualFree(
    _In_ PVOID Memory)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    SIZE_T sizeDummy = 0;

    if (Memory) {
        ntStatus = NtFreeVirtualMemory(
            NtCurrentProcess(),
            &Memory,
            &sizeDummy,
            MEM_RELEASE);
    }

    RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    return NT_SUCCESS(ntStatus);
}

/*
* supConvertToUnicode
*
* Purpose:
*
* Convert ANSI string to UNICODE string.
*
* N.B.
* If function succeeded - use RtlFreeUnicodeString to release allocated string.
*
*/
NTSTATUS supConvertToUnicode(
    _In_ LPCSTR AnsiString,
    _Inout_ PUNICODE_STRING UnicodeString)
{
    ANSI_STRING ansiString;

    RtlInitString(&ansiString, AnsiString);
    return RtlAnsiStringToUnicodeString(UnicodeString, &ansiString, TRUE);
}

/*
* supSignerIsMsft
*
* Purpose:
*
* Verify that signer is MSFT.
*
*/
BOOL supSignerIsMsft(
    _In_ PCCERT_CHAIN_CONTEXT pChainContext
)
{
    PCERT_SIMPLE_CHAIN pChain;
    PCCERT_CONTEXT pCertContext;

    pChain = pChainContext->rgpChain[0];
    pCertContext = pChain->rgpElement[0]->pCertContext;

    for (DWORD i = 0; i < PUBLISHER_NAME_LIST_CNT; i++) {

        BOOL trusted = TRUE;

        //
        // Check against all attributes.
        //
        for (DWORD j = 0; trusted && j < PUBLISHER_ATTR_CNT; j++) {

            LPWSTR attrString = NULL;
            DWORD attrStringLength;

            attrStringLength = CertGetNameString(
                pCertContext,
                CERT_NAME_ATTR_TYPE,
                0,
                (PVOID)gPublisherAttributeObjId[j],
                NULL,
                0);

            if (attrStringLength <= 1)
                return FALSE;

            attrString = (LPWSTR)supHeapAlloc(attrStringLength * sizeof(WCHAR));
            if (attrString == NULL)
                return FALSE;

            attrStringLength = CertGetNameString(
                pCertContext,
                CERT_NAME_ATTR_TYPE,
                0,
                (PVOID)gPublisherAttributeObjId[j],
                attrString,
                attrStringLength);

            if (attrStringLength <= 1 ||
                0 != _strcmp(attrString, gPublisherNameList[i][j]))
            {
                trusted = FALSE;
            }

            supHeapFree(attrString);
        }

        if (trusted)
            return TRUE;
    }

    return FALSE;
}

/*
* supxVerifyCatalogSignature
*
* Purpose:
*
* Verify if file is signed via catalog file rather than embedded signature.
*
*/
NTSTATUS supxVerifyCatalogSignature(
    _In_ HANDLE hFile,
    _Out_ PBOOL pbCatalogSigned
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    HANDLE hCatAdmin = NULL;
    HANDLE hCatInfo = NULL;
    CATALOG_INFO catalogInfo;
    BYTE* hash = NULL;
    DWORD hashSize = 0;

    *pbCatalogSigned = FALSE;

    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
        return STATUS_INVALID_PARAMETER;

    do {
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, NULL, 0))
            break;

        hash = (BYTE*)supHeapAlloc(hashSize);
        if (!hash)
            break;

        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash, 0))
            break;

        hCatInfo = CryptCATAdminEnumCatalogFromHash(
            hCatAdmin,
            hash,
            hashSize,
            0,
            NULL);

        if (hCatInfo) {
            RtlZeroMemory(&catalogInfo, sizeof(CATALOG_INFO));
            catalogInfo.cbStruct = sizeof(CATALOG_INFO);

            if (CryptCATCatalogInfoFromContext(hCatInfo, &catalogInfo, 0)) {
                *pbCatalogSigned = TRUE;
                ntStatus = STATUS_SUCCESS;
            }

            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        }
        else {
            ntStatus = STATUS_SUCCESS;
        }
    } while (FALSE);

    if (hash) supHeapFree(hash);
    if (hCatAdmin)
        CryptCATAdminReleaseContext(hCatAdmin, 0);

    return ntStatus;
}

/*
* supxVerifySignatureAlgorithmStrength
*
* Purpose:
*
* Verify that the signature uses sufficiently strong cryptographic algorithms.
*
*/
NTSTATUS supxVerifySignatureAlgorithmStrength(
    _In_ LPCWSTR lpFileName,
    _Out_ PBOOL pbStrongAlgorithm
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    DWORD dwEncoding, dwContentType, dwFormatType;
    DWORD dwSignerInfo = 0;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    CRYPT_ALGORITHM_IDENTIFIER* pAlgId;

    *pbStrongAlgorithm = FALSE;

    if (!CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        lpFileName,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding,
        &dwContentType,
        &dwFormatType,
        &hStore,
        &hMsg,
        NULL))
    {
        return STATUS_INVALID_PARAMETER;
    }

    do {
        if (!CryptMsgGetParam(
            hMsg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            NULL,
            &dwSignerInfo))
        {
            break;
        }

        pSignerInfo = (PCMSG_SIGNER_INFO)supHeapAlloc(dwSignerInfo);
        if (!pSignerInfo) {
            break;
        }

        if (!CryptMsgGetParam(
            hMsg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            (PVOID)pSignerInfo,
            &dwSignerInfo))
        {
            break;
        }

        pAlgId = &pSignerInfo->HashAlgorithm;

        if (_strcmp_a(pAlgId->pszObjId, szOID_NIST_sha256) == 0 ||
            _strcmp_a(pAlgId->pszObjId, szOID_NIST_sha384) == 0 ||
            _strcmp_a(pAlgId->pszObjId, szOID_NIST_sha512) == 0)
        {
            *pbStrongAlgorithm = TRUE;
        }

        ntStatus = STATUS_SUCCESS;
    } while (FALSE);

    if (pSignerInfo) supHeapFree(pSignerInfo);
    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);

    return ntStatus;
}

/*
* supxGetSignatureTimestamp
*
* Purpose:
*
* Extract timestamp from signature data.
*
*/
BOOL supxGetSignatureTimestamp(
    _In_ HANDLE hWVTStateData,
    _Out_ PFILETIME pTimeStamp
)
{
    BOOL result = FALSE;
    PCRYPT_PROVIDER_DATA pProvData;
    PCRYPT_PROVIDER_SGNR pProvSigner;

    if (hWVTStateData == NULL || pTimeStamp == NULL)
        return FALSE;

    RtlSecureZeroMemory(pTimeStamp, sizeof(FILETIME));

    pProvData = WTHelperProvDataFromStateData(hWVTStateData);
    if (pProvData) {
        pProvSigner = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
        if (pProvSigner) {
            if (pProvSigner->sftVerifyAsOf.dwLowDateTime || pProvSigner->sftVerifyAsOf.dwHighDateTime) {
                pTimeStamp->dwLowDateTime = pProvSigner->sftVerifyAsOf.dwLowDateTime;
                pTimeStamp->dwHighDateTime = pProvSigner->sftVerifyAsOf.dwHighDateTime;
                result = TRUE;
            }
        }
    }

    return result;
}

/*
* supxVerifyCertificateValidAtSigningTime
*
* Purpose:
*
* Check if certificate validity period includes signing time.
*
*/
BOOL supxVerifyCertificateValidAtSigningTime(
    _In_ HANDLE hWVTStateData,
    _In_ PFILETIME pSigningTime
)
{
    BOOL result = FALSE;
    PCRYPT_PROVIDER_DATA pProvData;
    PCRYPT_PROVIDER_SGNR pProvSigner;
    PCRYPT_PROVIDER_CERT pProvCert;
    PCCERT_CONTEXT pCertContext;

    if (hWVTStateData == NULL || pSigningTime == NULL)
        return FALSE;

    do {
        pProvData = WTHelperProvDataFromStateData(hWVTStateData);
        if (pProvData == NULL)
            break;
        pProvSigner = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
        if (pProvSigner == NULL)
            break;
        pProvCert = WTHelperGetProvCertFromChain(pProvSigner, 0);
        if (pProvCert == NULL)
            break;
        pCertContext = pProvCert->pCert;
        if (pCertContext == NULL)
            break;

        result = (CertVerifyTimeValidity(pSigningTime, pCertContext->pCertInfo) == 0);

    } while (FALSE);

    return result;
}

/*
* supxVerifyCatalogTrust
*
* Purpose:
*
* Locate the catalog file, verify the catalog signature,
* and check if the file hash is present in the catalog.
*/
NTSTATUS supxVerifyCatalogTrust(
    _In_ HANDLE hFile
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    HANDLE hCatAdmin = NULL;
    HANDLE hCatInfo = NULL;
    BYTE* hash = NULL;
    DWORD hashSize = 0;
    CATALOG_INFO catalogInfo;
    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_CATALOG_INFO catWintrust;
    WINTRUST_DATA wintrustData;
    LONG wintrustResult = ERROR_GEN_FAILURE;

    RtlZeroMemory(&catalogInfo, sizeof(CATALOG_INFO));
    RtlZeroMemory(&catWintrust, sizeof(WINTRUST_CATALOG_INFO));
    RtlZeroMemory(&wintrustData, sizeof(WINTRUST_DATA));
    catalogInfo.cbStruct = sizeof(CATALOG_INFO);

    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
        return STATUS_INVALID_PARAMETER;

    do {
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, NULL, 0))
            break;

        hash = (BYTE*)supHeapAlloc(hashSize);
        if (!hash)
            break;

        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash, 0))
            break;

        hCatInfo = CryptCATAdminEnumCatalogFromHash(
            hCatAdmin,
            hash,
            hashSize,
            0,
            NULL);

        if (!hCatInfo)
            break;

        if (!CryptCATCatalogInfoFromContext(hCatInfo, &catalogInfo, 0))
            break;

        catWintrust.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
        catWintrust.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
        catWintrust.pbCalculatedFileHash = hash;
        catWintrust.cbCalculatedFileHash = hashSize;
        catWintrust.pcwszMemberTag = NULL;
        catWintrust.pcwszMemberFilePath = NULL;

        wintrustData.cbStruct = sizeof(WINTRUST_DATA);
        wintrustData.dwUIChoice = WTD_UI_NONE;
        wintrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        wintrustData.dwUnionChoice = WTD_CHOICE_CATALOG;
        wintrustData.pCatalog = &catWintrust;
        wintrustData.dwStateAction = 0;
        wintrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        wintrustData.hWVTStateData = NULL;
        wintrustData.pPolicyCallbackData = NULL;
        wintrustData.pSIPClientData = NULL;

        wintrustResult = WinVerifyTrust(NULL, &guidAction, &wintrustData);
        if (wintrustResult == ERROR_SUCCESS)
            ntStatus = STATUS_SUCCESS;

    } while (FALSE);

    if (hash) supHeapFree(hash);
    if (hCatInfo)
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    if (hCatAdmin)
        CryptCATAdminReleaseContext(hCatAdmin, 0);

    return ntStatus;
}

/*
* supVerifyFileSignature
*
* Purpose:
*
* Validate file to be signed with a valid signature.
*
*/
NTSTATUS supVerifyFileSignature(
    _In_ KPROCESSOR_MODE Mode,
    _In_ LPWSTR lpFileName,
    _In_ BOOL OsBinaryCheck,
    _In_ ptrWTGetSignatureInfo pWTGetSignatureInfo
)
{
    BOOL bValid = FALSE, bTrustedFileOwner = FALSE, bStrongAlgorithm = FALSE, bCatalogSigned = FALSE;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    HANDLE hFile = NULL;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING usFileName;
    SIGNATURE_INFO sigData;
    FILETIME ftTimeStamp, ftNow;
    HANDLE hWVTStateData = NULL;
    DWORD dwFlags = SIF_BASE_VERIFICATION | SIF_CATALOG_SIGNED;

    if (pWTGetSignatureInfo == NULL)
        return STATUS_INVALID_PARAMETER_3;

    do {
        //
        // Open file and map it.
        //
        RtlInitEmptyUnicodeString(&usFileName, NULL, 0);
        if (RtlDosPathNameToNtPathName_U(lpFileName, &usFileName, NULL, NULL) == FALSE)
            break;

        InitializeObjectAttributes(&attr, &usFileName,
            OBJ_CASE_INSENSITIVE, NULL, NULL);

        RtlSecureZeroMemory(&iosb, sizeof(iosb));
        ntStatus = NtCreateFile(&hFile, SYNCHRONIZE | FILE_READ_DATA | READ_CONTROL,
            &attr, &iosb, NULL, 0, FILE_SHARE_READ, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

        if (!NT_SUCCESS(ntStatus))
            break;

        RtlSecureZeroMemory(&sigData, sizeof(sigData));
        sigData.cbSize = sizeof(sigData);

        ntStatus = supIsFileOwnedByTrustedInstallerSystemOrAdmins(Mode, hFile, &usFileName);
        bTrustedFileOwner = NT_SUCCESS(ntStatus);

        if (bTrustedFileOwner) {
            if (OsBinaryCheck) {
                dwFlags |= SIF_CHECK_OS_BINARY;
            }
            else {
                dwFlags |= SIF_AUTHENTICODE_SIGNED;
            }
        }
        else {
            //
            // FS object owner is untrusted, verify authenticode only.
            //
            dwFlags |= SIF_AUTHENTICODE_SIGNED;
        }

        ntStatus = pWTGetSignatureInfo(lpFileName,
            hFile,
            dwFlags,
            &sigData,
            NULL,
            &hWVTStateData);

        if (!NT_SUCCESS(ntStatus))
            break;

        //
        // Check if the file is catalog-signed.
        //
        ntStatus = supxVerifyCatalogSignature(hFile, &bCatalogSigned);
        if (NT_SUCCESS(ntStatus) && bCatalogSigned) {
            ntStatus = supxVerifyCatalogTrust(hFile);
            if (!NT_SUCCESS(ntStatus)) {
                break;
            }
        }

        //
        // Verify signature algorithm strength.
        //
        ntStatus = supxVerifySignatureAlgorithmStrength(lpFileName, &bStrongAlgorithm);
        if (!NT_SUCCESS(ntStatus)) {
            bStrongAlgorithm = FALSE;
        }

        //
        // For OS binaries require strong algorithm.
        //
        if (OsBinaryCheck && !bStrongAlgorithm) {
            ntStatus = STATUS_ENCRYPTION_FAILED;
            break;
        }

#if 0
        BOOL bTrustedPublisher = TRUE;

        if (Mode == UserMode) {
            //
            // Verify publisher.
            //
            CRYPT_PROVIDER_DATA* pCryptData;
            CRYPT_PROVIDER_SGNR* pSigner;

            pCryptData = WTHelperProvDataFromStateData(hWVTStateData);
            if (pCryptData) {
                pSigner = WTHelperGetProvSignerFromChain(pCryptData, 0, FALSE, 0);
                if (pSigner) {
                    bTrustedPublisher = supSignerIsMsft(pSigner->pChainContext);
                }
            }

            if (!bTrustedPublisher) {
                ntStatus = STATUS_IMAGE_CERT_REVOKED;
                break;
            }
        }
#endif

        if (bTrustedFileOwner) {
            if (OsBinaryCheck) {
                bValid = ((sigData.SignatureState == SIGNATURE_STATE_VALID) && (sigData.fOSBinary != FALSE));
            }
            else {
                bValid = (sigData.SignatureState == SIGNATURE_STATE_VALID);
            }
        }
        else {
            bValid = (sigData.SignatureState == SIGNATURE_STATE_VALID) &&
                (sigData.SignatureType == SIT_AUTHENTICODE);
        }

        if (bValid && hWVTStateData) {
            //
            // Verify signature timestamp.
            //
            if (supxGetSignatureTimestamp(hWVTStateData, &ftTimeStamp)) {
                GetSystemTimeAsFileTime(&ftNow);

                //
                // Verify timestamp is not in the future.
                //
                if (CompareFileTime(&ftTimeStamp, &ftNow) > 0) {
                    bValid = FALSE;
                    ntStatus = STATUS_TIME_DIFFERENCE_AT_DC;
                    break;
                }

                //
                // Verify certificate was valid at signing time.
                //
                if (!supxVerifyCertificateValidAtSigningTime(hWVTStateData, &ftTimeStamp)) {
                    bValid = FALSE;
                    ntStatus = STATUS_QUIC_TLS_CERTIFICATE_EXPIRED;
                    break;
                }
            }
        }

        ntStatus = bValid ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    } while (FALSE);

    if (hWVTStateData) {
        WINTRUST_DATA wintrustData;
    
        RtlSecureZeroMemory(&wintrustData, sizeof(wintrustData));
        wintrustData.cbStruct = sizeof(wintrustData);
        wintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        wintrustData.hWVTStateData = hWVTStateData;
        GUID guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WinVerifyTrust(NULL, &guid, &wintrustData);
        hWVTStateData = NULL;
    }

    if (hFile) NtClose(hFile);
    if (usFileName.Buffer != NULL)
        RtlFreeUnicodeString(&usFileName);

    return ntStatus;
}

/*
* supxFindFileVersion
*
* Purpose:
*
* Find VersionInfo block in data.
* (c) Vmprotect.
*
*/
PWSTR supxFindFileVersion(
    _In_ PBYTE DataPtr,
    _In_ SIZE_T DataSize
)
{
    PWCHAR data = (PWCHAR)DataPtr;
    SIZE_T dataSize = DataSize / sizeof(WCHAR);
    SIZE_T i;

    for (i = 0; i < dataSize; i++) {

        //
        // FileVersion + 00
        //
        if (i + 13 <= dataSize) {
            if (data[i + 0] == L'F' && data[i + 1] == L'i' &&
                data[i + 2] == L'l' && data[i + 3] == L'e' &&
                data[i + 4] == L'V' && data[i + 5] == L'e' &&
                data[i + 6] == L'r' && data[i + 7] == L's' &&
                data[i + 8] == L'i' && data[i + 9] == L'o' &&
                data[i + 10] == L'n' &&
                data[i + 11] == 0 && data[i + 12] == 0)
            {
                return data + i + 13;
            }
        }

        //
        // ProductVersion + 00
        // 
        if (i + 15 <= dataSize) {
            if (data[i + 0] == L'P' && data[i + 1] == L'r' &&
                data[i + 2] == L'o' && data[i + 3] == L'd' &&
                data[i + 4] == L'u' && data[i + 5] == L'c' &&
                data[i + 6] == L't' && data[i + 7] == L'V' &&
                data[i + 8] == L'e' && data[i + 9] == L'r' &&
                data[i + 10] == L's' && data[i + 11] == L'i' &&
                data[i + 12] == L'o' && data[i + 13] == L'n' &&
                data[i + 14] == 0)
            {
                return data + i + 15;
            }
        }
    }

    return NULL;
}

/*
* supParseOSBuildBumber
*
* Purpose:
*
* Extract build number from the version info resource.
* (c) Vmprotect.
*
*/
ULONG supParseOSBuildBumber(
    _In_ PVOID ImageBase
)
{
    ULONG result = 0, size;
    ULONG_PTR resStart, resEnd;
    ULONG RVA;
    PIMAGE_NT_HEADERS ntHeaders;

    if (!NT_SUCCESS(RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK,
        ImageBase, 0, &ntHeaders)))
    {
        return 0;
    }

    if (ntHeaders == NULL)
        return 0;

    RVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    if (RVA) {

        resStart = (ULONG_PTR)RtlOffsetToPointer(ImageBase, RVA);
        size = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        resEnd = (ULONG_PTR)RtlOffsetToPointer(resStart, size);

        while (wchar_t* fileVersion = supxFindFileVersion((PBYTE)resStart, resEnd - resStart)) {

            for (size_t i = 0; *fileVersion; fileVersion++) {
                if (*fileVersion == L'.')
                    i++;
                else if (i == 2) {
                    while (wchar_t c = *fileVersion++) {
                        if (c >= L'0' && c <= L'9') {
                            result *= 10;
                            result += c - L'0';
                        }
                        else
                            break;
                    }
                    break;
                }
            }

            if (IS_KNOWN_WINDOWS_BUILD(result))
                break;

            resStart = (ULONG_PTR)fileVersion;
        }
    }
    return result;
}

/*
* supMapNtdllCopy
*
* Purpose:
*
* Load copy of ntdll using selected method.
*
* 1. Map using absolute NT path
* 2. Map using relative NT path
* 3. Map using absolute KnownDlls object path
* 4. Map using relative KnownDlls object path
* 5. Map using precached ntdll directory handle
* ...
* Wubbaboo!
*
*/
NTSTATUS supMapNtdllCopy(
    _In_ NTDLL_MAP_METHOD MapMethod,
    _Out_ PVOID* BaseAddress
)
{
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING us;
    IO_STATUS_BLOCK iost;
    LARGE_INTEGER offset;
    HANDLE hObject = NULL, hFile = NULL, hSection = NULL;
    SIZE_T fileSize = 0;
    NTSTATUS ntStatus;

    *BaseAddress = NULL;

    LPWSTR lpPath = (LPWSTR)DIRECTORY_SYSTEM32;

    if (MapMethod == UseLdrKnownDllDirectoryHandle) {

        ntStatus = LdrGetKnownDllSectionHandle(RtlNtdllName, FALSE, &hSection);

    }
    else {

        if (MapMethod != UseKnownDllsAbsolute && MapMethod != UseKnownDllsRelative) {

            if (MapMethod == UseAbsolutePath)
                lpPath = (LPWSTR)L"\\systemroot\\system32\\ntdll.dll";

            RtlInitUnicodeString(&us, lpPath);
            InitializeObjectAttributes(&obja, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

            ntStatus = NtOpenFile(&hObject,
                FILE_GENERIC_READ | SYNCHRONIZE,
                &obja,
                &iost,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_SYNCHRONOUS_IO_NONALERT);

            if (MapMethod == UseRelativePath) {

                RtlInitUnicodeString(&us, RtlNtdllName);
                obja.RootDirectory = hObject;

                ntStatus = NtOpenFile(&hFile,
                    GENERIC_READ | SYNCHRONIZE,
                    &obja, &iost,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

            }
            else {
                hFile = hObject;
            }

            if (!NT_SUCCESS(ntStatus))
                return ntStatus;

            InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);

            ntStatus = NtCreateSection(&hSection,
                SECTION_MAP_READ,
                &obja,
                NULL,
                PAGE_READONLY,
                SEC_IMAGE_NO_EXECUTE,
                hFile);

            if (hFile)
                NtClose(hFile);

        }
        else {

            InitializeObjectAttributes(&obja, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);

            if (MapMethod == UseKnownDllsAbsolute) {
                RtlInitUnicodeString(&us, L"\\KnownDlls\\ntdll.dll");
            }
            else {

                RtlInitUnicodeString(&us, DIRECTORY_KNOWNDLLS);
                obja.ObjectName = &us;
                ntStatus = NtOpenDirectoryObject(&obja.RootDirectory,
                    DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
                    &obja);

                if (!NT_SUCCESS(ntStatus))
                    return ntStatus;

                RtlInitUnicodeString(&us, RtlNtdllName);
            }

            obja.ObjectName = &us;

            ntStatus = NtOpenSection(&hSection,
                SECTION_MAP_READ,
                &obja);

            if (obja.RootDirectory != NULL)
                NtClose(obja.RootDirectory);

        }
    }

    if (NT_SUCCESS(ntStatus)) {

        offset.QuadPart = 0;

        ntStatus = NtMapViewOfSection(hSection,
            NtCurrentProcess(),
            BaseAddress,
            0,
            0,
            &offset,
            &fileSize,
            ViewShare,
            0,
            PAGE_READONLY);

        NtClose(hSection);

    }

    return ntStatus;
}

/*
* supDetectDebug
*
* Purpose:
*
* Detect debugger/debugging by using selected method.
*
*/
BOOLEAN supDetectDebug(
    _In_ DBG_CHECK_METHOD Method
)
{
    SIZE_T drX = 0;
    ULONG_PTR val;
    CONTEXT* ctx;
    NTSTATUS ntStatus;
    ULONG returnLength = 0, noDebugInherit = 0;
    HANDLE debugObjectHandle = NULL;
    HANDLE debugPort = NULL;

    pfnNtQueryInformationProcess pNtQueryInformationProcess;

    switch (Method) {

    case CheckDrXReg:

        //
        // Non zero DrX registers in context record when catching exception.
        // This is handled by ScyllaHide.
        //

        __try {
            __writeeflags(__readeflags() | 0x100);
            val = __rdtsc();
            __nop();
            return TRUE;
        }
        __except (ctx = (GetExceptionInformation())->ContextRecord,
            drX = (ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS) ?
            ctx->Dr0 | ctx->Dr1 | ctx->Dr2 | ctx->Dr3 : 0,
            EXCEPTION_EXECUTE_HANDLER)
        {
            if (drX)
                return TRUE;
        }
        break;

        //
        // The only reliable methods of detecting debugger in a system.
        // Everything else are either bound to software bugs, 
        // user mode fake friendly or unstable and produces FP.
        //

    case CheckDebugObjectHandle:

        pNtQueryInformationProcess = (pfnNtQueryInformationProcess)SkiIndirectSystemCall;
        ntStatus = pNtQueryInformationProcess(NtCurrentProcess(),
            ProcessDebugObjectHandle,
            &debugObjectHandle,
            sizeof(debugObjectHandle),
            &returnLength);

        if (NT_SUCCESS(ntStatus)) {

            return (debugObjectHandle != NULL);
        }

        break;

    case CheckDebugPort:

        pNtQueryInformationProcess = (pfnNtQueryInformationProcess)SkiIndirectSystemCall;
        ntStatus = pNtQueryInformationProcess(NtCurrentProcess(),
            ProcessDebugPort,
            &debugPort,
            sizeof(debugPort),
            &returnLength);

        if (NT_SUCCESS(ntStatus)) {

            return (debugPort == (HANDLE)-1);
        }

        break;

    case CheckDebugFlags:

        pNtQueryInformationProcess = (pfnNtQueryInformationProcess)SkiIndirectSystemCall;
        ntStatus = pNtQueryInformationProcess(NtCurrentProcess(),
            ProcessDebugFlags,
            &noDebugInherit,
            sizeof(noDebugInherit),
            &returnLength);

        if (NT_SUCCESS(ntStatus)) {
            return (noDebugInherit == 0);
        }

        break;

    case CheckUSD:
        return USER_SHARED_DATA->KdDebuggerEnabled;

    }

    return FALSE;
}

/*
* supPrivilegeEnabled
*
* Purpose:
*
* Tests if the given token has the given privilege enabled/enabled by default.
*
*/
NTSTATUS supPrivilegeEnabled(
    _In_ HANDLE ClientToken,
    _In_ ULONG Privilege,
    _Out_ LPBOOL pfResult
)
{
    NTSTATUS status;
    PRIVILEGE_SET Privs;
    BOOLEAN bResult = FALSE;

    Privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    Privs.PrivilegeCount = 1;
    Privs.Privilege[0].Luid.LowPart = Privilege;
    Privs.Privilege[0].Luid.HighPart = 0;
    Privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED;

    status = NtPrivilegeCheck(ClientToken, &Privs, &bResult);

    *pfResult = bResult;

    return status;
}

/*
* supGetLoadedModulesList
*
* Purpose:
*
* Read list of loaded kernel modules.
*
*/
PVOID supGetLoadedModulesList(
    _In_ BOOL ExtendedOutput,
    _Out_opt_ PULONG ReturnLength
)
{
    NTSTATUS ntStatus;
    PVOID buffer;
    ULONG bufferSize = PAGE_SIZE;

    PRTL_PROCESS_MODULES pvModules;
    SYSTEM_INFORMATION_CLASS infoClass;

    if (ReturnLength)
        *ReturnLength = 0;

    if (ExtendedOutput)
        infoClass = SystemModuleInformationEx;
    else
        infoClass = SystemModuleInformation;

    buffer = supHeapAlloc((SIZE_T)bufferSize);
    if (buffer == NULL)
        return NULL;

    ntStatus = NtQuerySystemInformation(
        infoClass,
        buffer,
        bufferSize,
        &bufferSize);

    if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
        supHeapFree(buffer);
        buffer = supHeapAlloc((SIZE_T)bufferSize);

        ntStatus = NtQuerySystemInformation(
            infoClass,
            buffer,
            bufferSize,
            &bufferSize);
    }

    if (ReturnLength)
        *ReturnLength = bufferSize;

    //
    // Handle unexpected return.
    //
    // If driver image path exceeds structure field size then 
    // RtlUnicodeStringToAnsiString will throw STATUS_BUFFER_OVERFLOW.
    // 
    // If this is the last driver in the enumeration service will return 
    // valid data but STATUS_BUFFER_OVERFLOW in result.
    //
    if (ntStatus == STATUS_BUFFER_OVERFLOW) {

        //
        // Force ignore this status if list is not empty.
        //
        pvModules = (PRTL_PROCESS_MODULES)buffer;
        if (pvModules->NumberOfModules != 0)
            return buffer;
    }

    if (NT_SUCCESS(ntStatus)) {
        return buffer;
    }

    if (buffer)
        supHeapFree(buffer);

    return NULL;
}

//
// Conversion buffer size
//
#define CONVERT_NTNAME_BUFFER_SIZE 512

/*
* supConvertFileName
*
* Purpose:
*
* Translate Nt path name to Dos path name.
*
*/
BOOL supConvertFileName(
    _In_ LPWSTR NtFileName,
    _Inout_ LPWSTR DosFileName,
    _In_ SIZE_T ccDosFileName
)
{
    BOOL bFound = FALSE;

    SIZE_T nLen;

    WCHAR szDrive[3];
    WCHAR szName[MAX_PATH];
    WCHAR szTemp[CONVERT_NTNAME_BUFFER_SIZE];
    WCHAR* pszTemp;

    //
    // All input parameters are validated by caller before.
    //

    //
    // Drive template.
    //
    szDrive[0] = L'X';
    szDrive[1] = L':';
    szDrive[2] = 0;

    //
    // Query array of logical disk drive strings.
    //
    szTemp[0] = 0;
    if (GetLogicalDriveStrings(RTL_NUMBER_OF(szTemp), szTemp) == 0)
        return FALSE;

    pszTemp = szTemp;

    do {

        //
        // Copy the drive letter to the template string.
        //
        *szDrive = *pszTemp;
        szName[0] = 0;

        //
        // Lookup each device name.
        //
        if (QueryDosDevice(szDrive, szName, MAX_PATH)) {

            nLen = _strlen(szName);

            if (nLen < MAX_PATH) {

                //
                // Match device name.
                //
                bFound = ((_strncmpi(NtFileName, szName, nLen) == 0)
                    && *(NtFileName + nLen) == L'\\');

                if (bFound) {

                    //
                    // Build output name.
                    //
                    StringCchPrintf(DosFileName,
                        ccDosFileName,
                        TEXT("%ws%ws"),
                        szDrive,
                        NtFileName + nLen);

                }

            }

        }

        //
        // Go to the next NULL character, i.e. the next drive name.
        //
        while (*pszTemp++);

    } while (!bFound && *pszTemp);

    return bFound;
}

/*
* supQueryObjectInformation
*
* Purpose:
*
* Wrapper around NtQueryObject.
*
*/
NTSTATUS supQueryObjectInformation(
    _In_opt_ HANDLE ObjectHandle,
    _In_ OBJECT_INFORMATION_CLASS InformationClass,
    _Out_ PVOID* Buffer,
    _Out_opt_ PULONG ReturnLength
)
{
    NTSTATUS ntStatus;
    PVOID queryBuffer;
    ULONG returnLength = 0;

    *Buffer = NULL;
    if (ReturnLength) *ReturnLength = 0;

    ntStatus = NtQueryObject(ObjectHandle,
        InformationClass,
        NULL,
        0,
        &returnLength);

    //
    // Test all possible acceptable failures.
    //
    if (ntStatus != STATUS_BUFFER_OVERFLOW &&
        ntStatus != STATUS_BUFFER_TOO_SMALL &&
        ntStatus != STATUS_INFO_LENGTH_MISMATCH)
    {
        return ntStatus;
    }

    //
    // Check return length for reasonable value.
    //
    if (returnLength == 0 || returnLength > NTQOI_MAX_BUFER_LENGTH) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    queryBuffer = supHeapAlloc(returnLength);
    if (queryBuffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    ntStatus = NtQueryObject(ObjectHandle,
        InformationClass,
        queryBuffer,
        returnLength,
        &returnLength);

    if (NT_SUCCESS(ntStatus)) {
        *Buffer = queryBuffer;
        if (ReturnLength) *ReturnLength = returnLength;
    }
    else {
        supHeapFree(queryBuffer);
    }

    return ntStatus;
}

/*
* supGetWin32FileName
*
* Purpose:
*
* Query filename by handle.
*
*/
NTSTATUS supGetWin32FileName(
    _In_ LPCWSTR NtFileName,
    _Out_ LPWSTR* Win32FileName
)
{
    BOOL bResult = FALSE;
    LPWSTR lpWin32Name = NULL;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    HANDLE hFile = NULL;
    UNICODE_STRING usNtFileName;
    OBJECT_ATTRIBUTES obja;
    IO_STATUS_BLOCK iost;
    ULONG size;

    BYTE* Buffer = NULL;
    *Win32FileName = NULL;

    RtlInitUnicodeString(&usNtFileName, NtFileName);
    InitializeObjectAttributes(&obja, &usNtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

    do {

        ntStatus = NtCreateFile(&hFile,
            SYNCHRONIZE,
            &obja,
            &iost,
            NULL,
            0,
            FILE_SHARE_VALID_FLAGS,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            NULL, 0);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = supQueryObjectInformation(hFile,
            ObjectNameInformation,
            (PVOID*)&Buffer,
            NULL);

        if (!NT_SUCCESS(ntStatus))
            break;

        size = UNICODE_STRING_MAX_CHARS * sizeof(WCHAR);
        lpWin32Name = (LPWSTR)supHeapAlloc(size);

        if (lpWin32Name == NULL) {
            ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
            break;
        }

        bResult = supConvertFileName(((POBJECT_NAME_INFORMATION)Buffer)->Name.Buffer,
            lpWin32Name,
            size / sizeof(WCHAR));

        if (!bResult) {
            ntStatus = STATUS_UNSUCCESSFUL;
        }

    } while (FALSE);

    if (Buffer) supHeapFree(Buffer);
    if (hFile) NtClose(hFile);
    if (bResult == FALSE && lpWin32Name) {
        supHeapFree(lpWin32Name);
        lpWin32Name = NULL;
    }
    *Win32FileName = lpWin32Name;

    return ntStatus;
}

/*
* supxDetectObjectCallback
*
* Purpose:
*
* Comparer callback routine used in objects enumeration.
*
*/
NTSTATUS NTAPI supxDetectObjectCallback(
    _In_ POBJECT_DIRECTORY_INFORMATION Entry,
    _In_ PVOID CallbackParam
)
{
    POBJSCANPARAM Param = (POBJSCANPARAM)CallbackParam;

    if (Entry == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (CallbackParam == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Param->Buffer == NULL || Param->BufferSize == 0) {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    if (Entry->Name.Buffer) {
        if (_strcmpi_w(Entry->Name.Buffer, Param->Buffer) == 0) {
            return STATUS_SUCCESS;
        }
    }
    return STATUS_UNSUCCESSFUL;
}

/*
* supxEnumSystemObjects
*
* Purpose:
*
* Lookup object by name in given directory.
*
*/
NTSTATUS NTAPI supxEnumSystemObjects(
    _In_opt_ LPCWSTR pwszRootDirectory,
    _In_opt_ HANDLE hRootDirectory,
    _In_ PENUMOBJECTSCALLBACK CallbackProc,
    _In_opt_ PVOID CallbackParam
)
{
    ULONG ctx, rlen;
    HANDLE hDirectory = NULL;
    NTSTATUS status;
    NTSTATUS CallbackStatus;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING sname;

    POBJECT_DIRECTORY_INFORMATION    objinf;

    if (CallbackProc == NULL) {
        return STATUS_INVALID_PARAMETER_4;
    }

    status = STATUS_UNSUCCESSFUL;

    // We can use root directory.
    if (pwszRootDirectory != NULL) {
        RtlSecureZeroMemory(&sname, sizeof(sname));
        RtlInitUnicodeString(&sname, pwszRootDirectory);
        InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    else {
        if (hRootDirectory == NULL) {
            return STATUS_INVALID_PARAMETER_2;
        }
        hDirectory = hRootDirectory;
    }

    // Enumerate objects in directory.
    ctx = 0;
    do {

        rlen = 0;
        status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
        if (status != STATUS_BUFFER_TOO_SMALL)
            break;

        objinf = (POBJECT_DIRECTORY_INFORMATION)supHeapAlloc(rlen);
        if (objinf == NULL)
            break;

        status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
        if (!NT_SUCCESS(status)) {
            supHeapFree(objinf);
            break;
        }

        CallbackStatus = CallbackProc(objinf, CallbackParam);

        supHeapFree(objinf);

        if (NT_SUCCESS(CallbackStatus)) {
            status = STATUS_SUCCESS;
            break;
        }

    } while (TRUE);

    if (hDirectory != NULL) {
        NtClose(hDirectory);
    }

    return status;
}

/*
* supIsObjectExists
*
* Purpose:
*
* Return TRUE if the given object exists, FALSE otherwise.
*
*/
BOOLEAN supIsObjectExists(
    _In_ LPCWSTR RootDirectory,
    _In_ LPCWSTR ObjectName
)
{
    OBJSCANPARAM Param;

    Param.Buffer = ObjectName;
    Param.BufferSize = (ULONG)_strlen(ObjectName);

    return NT_SUCCESS(supxEnumSystemObjects(RootDirectory, NULL, supxDetectObjectCallback, &Param));
}

/*
* supEmptyWorkingSet
*
* Purpose:
*
* Empty process working set.
*
*/
NTSTATUS supEmptyWorkingSet()
{
    NTSTATUS ntStatus;
    QUOTA_LIMITS quotaLimits;

    ntStatus = NtQueryInformationProcess(NtCurrentProcess(),
        ProcessQuotaLimits,
        &quotaLimits,
        sizeof(quotaLimits),
        NULL);

    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }

    quotaLimits.MinimumWorkingSetSize = (SIZE_T)-1;
    quotaLimits.MaximumWorkingSetSize = (SIZE_T)-1;

    return NtSetInformationProcess(NtCurrentProcess(),
        ProcessQuotaLimits,
        &quotaLimits,
        sizeof(quotaLimits));
}

/*
* supFindModuleEntryByAddress
*
* Purpose:
*
* Find Module Entry for given Address.
*
*/
BOOL supFindModuleEntryByAddress(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ PVOID Address,
    _Out_ PULONG ModuleIndex
)
{
    ULONG i, modulesCount = pModulesList->NumberOfModules;

    *ModuleIndex = 0;

    for (i = 0; i < modulesCount; i++) {
        if (IN_REGION(Address,
            pModulesList->Modules[i].ImageBase,
            pModulesList->Modules[i].ImageSize))
        {
            *ModuleIndex = i;
            return TRUE;
        }
    }
    return FALSE;
}

/*
* supxListViewExportCSV
*
* Purpose:
*
* Export listview entries into file in csv format.
*
*/
BOOL supxListViewExportCSV(_In_ HWND List, _In_ PWCHAR FileName)
{
    HWND hdr;
    HDITEM headerItem;
    LVITEM lvItem;
    PWCHAR buffer = NULL, writePtr = NULL;
    PWCHAR text = NULL;
    INT rowCount, colCount, row, col;
    SIZE_T totalSize = 0, requiredSize;
    BOOL result = FALSE;
    HANDLE hFile = NULL;
    DWORD bytesWritten;

    text = (PWCHAR)supVirtualAlloc((UNICODE_STRING_MAX_CHARS + 1) * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (text == NULL)
        return FALSE;

    do {
        hdr = ListView_GetHeader(List);
        colCount = Header_GetItemCount(hdr);
        rowCount = ListView_GetItemCount(List);

        if (colCount == 0 || rowCount == 0)
            break;

        totalSize = (rowCount + 1) * colCount * 256;
        buffer = (PWCHAR)supVirtualAlloc(totalSize * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (buffer == NULL)
            break;

        writePtr = buffer;

        headerItem.mask = HDI_TEXT | HDI_ORDER;
        headerItem.pszText = text;
        headerItem.cchTextMax = UNICODE_STRING_MAX_CHARS;

        lvItem.mask = LVIF_TEXT;
        lvItem.pszText = text;
        lvItem.cchTextMax = UNICODE_STRING_MAX_CHARS;

        for (col = 0; col < colCount; col++) {
            text[0] = L'\0';
            headerItem.iOrder = col;
            Header_GetItem(hdr, col, &headerItem);

            *writePtr++ = L'"';
            for (PWCHAR p = text; *p; p++) {
                *writePtr++ = *p;
                if (*p == L'"')
                    *writePtr++ = L'"';
            }
            *writePtr++ = L'"';

            if (col < colCount - 1)
                *writePtr++ = L',';
        }
        *writePtr++ = L'\r';
        *writePtr++ = L'\n';

        for (row = 0; row < rowCount; row++) {
            for (col = 0; col < colCount; col++) {
                text[0] = L'\0';
                lvItem.iItem = row;
                lvItem.iSubItem = col;
                ListView_GetItem(List, &lvItem);

                *writePtr++ = L'"';
                for (PWCHAR p = text; *p; p++) {
                    *writePtr++ = *p;
                    if (*p == L'"')
                        *writePtr++ = L'"';
                }
                *writePtr++ = L'"';

                if (col < colCount - 1)
                    *writePtr++ = L',';
            }
            *writePtr++ = L'\r';
            *writePtr++ = L'\n';
        }
        *writePtr = L'\0';

        hFile = CreateFile(FileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            requiredSize = (SIZE_T)((ULONG_PTR)writePtr - (ULONG_PTR)buffer);
            result = WriteFile(hFile, buffer, (DWORD)requiredSize, &bytesWritten, NULL);
            CloseHandle(hFile);
        }

    } while (FALSE);

    supVirtualFree(text);
    if (buffer) supVirtualFree(buffer);
    return result;
}

/*
* supSaveDialogExecute
*
* Purpose:
*
* Display SaveDialog.
*
*/
BOOL supSaveDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR SaveFileName,
    _In_ LPCWSTR DialogFilter
)
{
    OPENFILENAME tag1;

    RtlSecureZeroMemory(&tag1, sizeof(OPENFILENAME));

    tag1.lStructSize = sizeof(OPENFILENAME);
    tag1.hwndOwner = OwnerWindow;
    tag1.lpstrFilter = DialogFilter;
    tag1.lpstrFile = SaveFileName;
    tag1.nMaxFile = MAX_PATH;
    tag1.lpstrInitialDir = NULL;
    tag1.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    return GetSaveFileName(&tag1);
}

/*
* supSetWaitCursor
*
* Purpose:
*
* Sets cursor state.
*
*/
VOID supSetWaitCursor(
    _In_ BOOL fSet
)
{
    ShowCursor(fSet);
    SetCursor(LoadCursor(NULL, fSet ? IDC_WAIT : IDC_ARROW));
}

/*
* supShowWelcomeBanner
*
* Purpose:
*
* Display Skilla version information.
*
*/
VOID supShowWelcomeBanner()
{
    WCHAR szText[200];

    LARGE_INTEGER startTime;
    TIME_FIELDS systemTime;

    GetSystemTimeAsFileTime((LPFILETIME)&startTime);
    FileTimeToLocalFileTime((PFILETIME)&startTime, (PFILETIME)&startTime);
    RtlTimeToTimeFields((PLARGE_INTEGER)&startTime, (PTIME_FIELDS)&systemTime);

    StringCchPrintf(szText,
        RTL_NUMBER_OF(szText),
        L"%ws v%lu.%lu.%lu, started at %02hd.%02hd.%04hd %02hd:%02hd:%02hd",
        PROGRAM_NAME,
        SK_VERSION_MAJOR,
        SK_VERSION_MINOR,
        SK_VERSION_BUILD,
        systemTime.Day,
        systemTime.Month,
        systemTime.Year,
        systemTime.Hour,
        systemTime.Minute,
        systemTime.Second);

    supReportEvent(evtInformation,
        szText,
        NULL,
        NULL);

    StringCchPrintf(szText,
        RTL_NUMBER_OF(szText),
        L"%ws build at %ws %ws",
        PROGRAM_NAME,
        TEXT(__DATE__),
        TEXT(__TIME__));

    supStatusBarSetText(hwndStatusBar, 0, szText);

    //
    // Show general usage help.
    //

    supReportEvent(evtInformation,
        (LPWSTR)TEXT("Use File->Scan or press F5 to start a scan"),
        NULL,
        NULL);

    supReportEvent(evtInformation,
        (LPWSTR)TEXT("Use Probes->Settings or press F2 to change scan settings"),
        NULL,
        NULL);
}

/*
* supInitializeSecurityForCOM
*
* Purpose:
*
* Setup COM security for a process.
*
*/
BOOL supInitializeSecurityForCOM()
{
    HRESULT hr = CoInitializeSecurity(NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_SECURE_REFS,
        NULL);

    if (hr != S_OK &&
        hr != RPC_E_TOO_LATE)
    {
        REPORT_RIP(TEXT("Could not initialize COM security"));
        return FALSE;
    }

    return TRUE;
}

/*
* supListViewExportToFile
*
* Purpose:
*
* Export listview contents to the specified file.
*
*/
BOOL supListViewExportToFile(
    _In_ LPCWSTR FileName,
    _In_ HWND WindowHandle,
    _In_ HWND ListView
)
{
    BOOL bResult = FALSE;
    WCHAR szExportFileName[MAX_PATH + 1];

    RtlSecureZeroMemory(&szExportFileName, sizeof(szExportFileName));

    _strcpy(szExportFileName, FileName);
    if (supSaveDialogExecute(WindowHandle,
        (LPWSTR)&szExportFileName,
        T_CSV_FILE_FILTER))
    {
        SetCapture(WindowHandle);
        supSetWaitCursor(TRUE);

        bResult = supxListViewExportCSV(ListView, szExportFileName);

        supSetWaitCursor(FALSE);
        ReleaseCapture();
    }

    return bResult;
}

/*
* supGetMappedFileName
*
* Purpose:
*
* Returns the name of the memory-mapped file if possible.
*
*/
NTSTATUS supGetMappedFileName(
    _In_ PVOID lpAddress,
    _Out_ POBJECT_NAME_INFORMATION* ObjectNameInformation
)
{
    NTSTATUS ntStatus;
    SIZE_T returnedLength = 0;
    POBJECT_NAME_INFORMATION objectNameInfo = NULL;

    do {
        ntStatus = NtQueryVirtualMemory(
            NtCurrentProcess(),
            lpAddress,
            MemoryMappedFilenameInformation,
            NULL,
            0,
            &returnedLength);

        if (ntStatus != STATUS_INFO_LENGTH_MISMATCH)
            break;

        objectNameInfo = (OBJECT_NAME_INFORMATION*)supHeapAlloc(returnedLength);
        if (objectNameInfo == NULL)
            break;

        ntStatus = NtQueryVirtualMemory(
            NtCurrentProcess(),
            lpAddress,
            MemoryMappedFilenameInformation,
            objectNameInfo,
            returnedLength,
            &returnedLength);

        if (!NT_SUCCESS(ntStatus)) {
            supHeapFree(objectNameInfo);
            objectNameInfo = NULL;
        }

    } while (FALSE);

    *ObjectNameInformation = objectNameInfo;

    return ntStatus;
}

/*
* supGetConsoleHostForSelf
*
* Purpose:
*
* Return process console host pid.
*
*/
NTSTATUS supGetConsoleHostForSelf(
    _Out_ PHANDLE ConsoleHostId)
{
    ULONG returnLength;
    return NtQueryInformationProcess(NtCurrentProcess(),
        ProcessConsoleHostProcess,
        (PVOID)ConsoleHostId,
        sizeof(HANDLE),
        &returnLength);
}

/*
* supQueryImageInformation
*
* Purpose:
*
* Returns ImageBase/SizeOfImage for the given address if there is any image.
*
*/
NTSTATUS supQueryImageInformation(
    _In_ PVOID Address,
    _Out_ PVOID* ImageBase,
    _Out_ PSIZE_T SizeOfImage
)
{
    NTSTATUS ntStatus;
    SIZE_T memIO;
    MEMORY_IMAGE_INFORMATION mim;

    *ImageBase = NULL;
    *SizeOfImage = 0;

    ntStatus = NtQueryVirtualMemory(NtCurrentProcess(),
        Address,
        MemoryImageInformation,
        &mim,
        sizeof(MEMORY_IMAGE_INFORMATION),
        &memIO);

    if (NT_SUCCESS(ntStatus)) {
        *ImageBase = mim.ImageBase;
        *SizeOfImage = mim.SizeOfImage;
    }

    return ntStatus;
}

/*
* supQueryThreadStartAddress
*
* Purpose:
*
* Returns system and win32 thread entry points.
*
*/
NTSTATUS supQueryThreadStartAddress(
    _In_ HANDLE ThreadHandle,
    _Out_ SUP_THREAD_INFO* ThreadInformation
)
{
    NTSTATUS ntStatus;
    ULONG returnLength;
    PVOID threadStartAddress = NULL;
    SYSTEM_THREAD_INFORMATION sti;

    ntStatus = NtQueryInformationThread(ThreadHandle,
        ThreadSystemThreadInformation, &sti, sizeof(sti), &returnLength);

    ntStatus |= NtQueryInformationThread(ThreadHandle,
        ThreadQuerySetWin32StartAddress, &threadStartAddress, sizeof(threadStartAddress), &returnLength);

    ThreadInformation->StartAddress = sti.StartAddress;
    ThreadInformation->Win32StartAddress = threadStartAddress;

    return ntStatus;
}

/*
* supQueryThreadInstructionPointer
*
* Purpose:
*
* Return thread context rip.
*
*/
NTSTATUS supQueryThreadInstructionPointer(
    _In_ HANDLE Threadhandle,
    _Out_ PDWORD64 InstructionPointer
)
{
    CONTEXT threadCtx;
    NTSTATUS ntStatus;

    RtlSecureZeroMemory(&threadCtx, sizeof(threadCtx));
    threadCtx.ContextFlags = CONTEXT_CONTROL;

    ntStatus = NtGetContextThread(Threadhandle, &threadCtx);

    if (NT_SUCCESS(ntStatus))
        *InstructionPointer = threadCtx.Rip;
    else
        *InstructionPointer = 0;

    return ntStatus;
}

/*
*
* NT STUBS
*
*/

PUSH_DISABLE_WARNING(6387)

NTSTUB_ROUTINE(supStubNtQueryInformationProcess)
{
    ULONG returnLength;

    return NtQueryInformationProcess(NtCurrentProcess(),
        ProcessBasicInformation, NULL, 0, &returnLength);
}

NTSTUB_ROUTINE(supStubNtQueryInformationThread)
{
    ULONG returnLength;

    return NtQueryInformationThread(NtCurrentThread(),
        ThreadBasicInformation, NULL, 0, &returnLength);
}

NTSTUB_ROUTINE(supStubNtQuerySystemInformation)
{
    ULONG returnLength;

    return NtQuerySystemInformation(SystemBasicInformation,
        NULL, 0, &returnLength);
}

NTSTUB_ROUTINE(supStubNtSetInformationThread)
{
    return NtSetInformationThread(0,
        ThreadAffinityMask, NULL, 0);
}

NTSTUB_ROUTINE(supStubNtSetInformationProcess)
{
    return NtSetInformationProcess(NtCurrentProcess(),
        ProcessAffinityMask, NULL, 0);
}

NTSTUB_ROUTINE(supStubNtGetContextThread)
{
    return NtGetContextThread(NtCurrentThread(),
        NULL);
}

NTSTUB_ROUTINE(supStubNtSetContextThread)
{
    return NtSetContextThread(NtCurrentThread(),
        NULL);
}

NTSTUB_ROUTINE(supStubNtClose)
{
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (hEvent)
        return NtClose(hEvent);
    return STATUS_UNSUCCESSFUL;
}

NTSTUB_ROUTINE(supStubNtDuplicateObject)
{
    return NtDuplicateObject(NtCurrentProcess(),
        NULL,
        NtCurrentProcess(),
        NULL,
        MAXIMUM_ALLOWED,
        0,
        DUPLICATE_SAME_ACCESS);
}

NTSTUB_ROUTINE(supStubNtQueryObject)
{
    ULONG returnLength;

    return NtQueryObject(NtCurrentProcess(),
        ObjectBasicInformation,
        NULL,
        0,
        &returnLength);
}

NTSTUB_ROUTINE(supStubNtOpenFile)
{
    return NtOpenFile(NULL,
        GENERIC_ALL,
        NULL,
        NULL,
        0,
        0);
}

NTSTUB_ROUTINE(supStubNtCreateSection)
{
    return NtCreateSection(NULL,
        0,
        NULL,
        NULL,
        0,
        0,
        NULL);
}

NTSTUB_ROUTINE(supStubNtMapViewOfSection)
{
    return NtMapViewOfSection(NULL,
        NULL,
        NULL,
        0,
        0,
        NULL,
        NULL,
        ViewShare,
        0,
        0);
}

NTSTUB_ROUTINE(supStubNtQueryVirtualMemory)
{
    SIZE_T returnLength;

    return NtQueryVirtualMemory(NULL,
        NULL,
        MemoryBasicInformation,
        NULL,
        0,
        &returnLength);
}

NTSTUB_ROUTINE(supStubNtContinue)
{
    return NtContinue(NULL, FALSE);
}

NTSTUB_ROUTINE(supStubNtResumeThread)
{
    return NtResumeThread(NULL, NULL);
}

NTSTUB_ROUTINE(supStubNtCreateThreadEx)
{
    return NtCreateThreadEx(NULL,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        0,
        0,
        0,
        0,
        NULL);
}

NTSTUB_ROUTINE(supStubNtQueryPerformanceCounter)
{
    return NtQueryPerformanceCounter(NULL, NULL);
}

POP_DISABLE_WARNING(6387)

SUP_NTSTUB supNtStubs[] = {
    {"NtQueryInformationProcess", supStubNtQueryInformationProcess },
    {"NtQueryInformationThread", supStubNtQueryInformationThread },
    {"NtQuerySystemInformation", supStubNtQuerySystemInformation },
    {"NtSetInformationThread", supStubNtSetInformationThread },
    {"NtSetInformationProcess", supStubNtSetInformationProcess },
    {"NtGetContextThread", supStubNtGetContextThread },
    {"NtSetContextThread", supStubNtSetContextThread },
    {"NtClose", supStubNtClose },
    {"NtDuplicateObject", supStubNtDuplicateObject },
    {"NtQueryObject", supStubNtQueryObject },
    {"NtOpenFile", supStubNtOpenFile },
    {"NtCreateSection", supStubNtCreateSection },
    {"NtMapViewOfSection", supStubNtMapViewOfSection },
    {"NtQueryVirtualMemory", supStubNtQueryVirtualMemory },
    {"NtContinue", supStubNtContinue },
    {"NtResumeThread", supStubNtResumeThread },
    {"NtCreateThreadEx", supStubNtCreateThreadEx },
    {"NtQueryPerformanceCounter", supStubNtQueryPerformanceCounter }
};

/*
* supGetNtStubByName
*
* Purpose:
*
* Return stub by name.
*
*/
PVOID supGetNtStubByName(
    _In_ LPCSTR lpName)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(supNtStubs); i++)
        if (_strcmpi_a(supNtStubs[i].Name, lpName) == 0)
            return supNtStubs[i].Stub;

    return NULL;
}

/*
* supInitializeKnownSids
*
* Purpose:
*
* Create some well-known sids.
*
*/
NTSTATUS supInitializeKnownSids()
{
    NTSTATUS ntStatus;
    SID_IDENTIFIER_AUTHORITY NtAuth = SECURITY_NT_AUTHORITY;

    ntStatus = RtlInitializeSid(&gLocalSystemSid, &NtAuth, 1);
    if (NT_SUCCESS(ntStatus)) {

        *RtlSubAuthoritySid(&gLocalSystemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;

        ntStatus = RtlInitializeSid(&gAdminsGroupSid, &NtAuth, 2);
        if (NT_SUCCESS(ntStatus)) {

            *RtlSubAuthoritySid(&gAdminsGroupSid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
            *RtlSubAuthoritySid(&gAdminsGroupSid, 1) = DOMAIN_ALIAS_RID_ADMINS;

            ntStatus = RtlInitializeSid(&gTrustedInstallerSid, &NtAuth, SECURITY_SERVICE_ID_RID_COUNT);
            if (NT_SUCCESS(ntStatus)) {

                //
                // Trusted Installer SID 956008885-3418522649-1831038044-1853292631-2271478464
                //
                *RtlSubAuthoritySid(&gTrustedInstallerSid, 0) = SECURITY_SERVICE_ID_BASE_RID;
                *RtlSubAuthoritySid(&gTrustedInstallerSid, 1) = 956008885;
                *RtlSubAuthoritySid(&gTrustedInstallerSid, 2) = 3418522649;
                *RtlSubAuthoritySid(&gTrustedInstallerSid, 3) = 1831038044;
                *RtlSubAuthoritySid(&gTrustedInstallerSid, 4) = 1853292631;
                *RtlSubAuthoritySid(&gTrustedInstallerSid, 5) = 2271478464;

            }
        }
    }

    return ntStatus;
}

/*
* supLookupEntryInKnownDllsCache
*
* Purpose:
*
* Find cached entry.
*
*/
BOOL supLookupEntryInKnownDllsCache(
    _In_ PUNICODE_STRING LookupName,
    _In_ PUNICODE_STRING LookupType
)
{
    PLIST_ENTRY nextEntry;
    PSUP_KNOWNDLLS_ENTRY dllEntry;
    ULONG nameHash, typeHash;

    RtlHashUnicodeString(LookupName, FALSE, HASH_STRING_ALGORITHM_X65599, &nameHash);
    RtlHashUnicodeString(LookupType, FALSE, HASH_STRING_ALGORITHM_X65599, &typeHash);

    for (nextEntry = gKnownDllsHead.Flink;
        nextEntry != &gKnownDllsHead;
        nextEntry = nextEntry->Flink)
    {
        dllEntry = CONTAINING_RECORD(nextEntry, SUP_KNOWNDLLS_ENTRY, ListEntry);
        if (dllEntry->NameHash == nameHash &&
            dllEntry->TypeHash == typeHash)
        {
            return TRUE;
        }
    }

    return FALSE;
}

/*
* supCacheKnownDllsEntries
*
* Purpose:
*
* Create cache for KnownDlls directory entries.
*
*/
VOID supCacheKnownDllsEntries()
{
    NTSTATUS ntStatus;
    ULONG ctx, returnLength;
    POBJECT_DIRECTORY_INFORMATION pDirInfo;
    HANDLE hDirectory = NULL;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING us;
    SUP_KNOWNDLLS_ENTRY* pEntry;

    InitializeListHead(&gKnownDllsHead);
    RtlInitUnicodeString(&us, DIRECTORY_KNOWNDLLS);
    InitializeObjectAttributes(&obja, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    ntStatus = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &obja);

    if (NT_SUCCESS(ntStatus)) {

        ctx = 0;
        do {

            returnLength = 0;
            ntStatus = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &returnLength);
            if (ntStatus != STATUS_BUFFER_TOO_SMALL)
                break;

            pDirInfo = (POBJECT_DIRECTORY_INFORMATION)supHeapAlloc(returnLength);
            if (pDirInfo == NULL)
                break;

            ntStatus = NtQueryDirectoryObject(hDirectory, pDirInfo, returnLength, TRUE, FALSE, &ctx, &returnLength);
            if (!NT_SUCCESS(ntStatus)) {
                supHeapFree(pDirInfo);
                break;
            }

            pEntry = (PSUP_KNOWNDLLS_ENTRY)supHeapAlloc(sizeof(SUP_KNOWNDLLS_ENTRY));
            if (pEntry) {

                RtlHashUnicodeString(&pDirInfo->Name, FALSE, HASH_STRING_ALGORITHM_X65599, &pEntry->NameHash);
                RtlHashUnicodeString(&pDirInfo->TypeName, FALSE, HASH_STRING_ALGORITHM_X65599, &pEntry->TypeHash);
                InsertTailList(&gKnownDllsHead, &pEntry->ListEntry);

            }
            supHeapFree(pDirInfo);

        } while (TRUE);

        NtClose(hDirectory);
    }
}

/*
* supMapImageNoExecute
*
* Purpose:
*
* Map image with SEC_IMAGE_NO_EXECUTE.
*
*/
NTSTATUS supMapImageNoExecute(
    _In_ PUNICODE_STRING ImagePath,
    _Out_ PVOID* BaseAddress
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL, hSection = NULL;
    OBJECT_ATTRIBUTES obja;
    IO_STATUS_BLOCK iost;
    LARGE_INTEGER li;

    *BaseAddress = NULL;

    do {

        InitializeObjectAttributes(&obja, ImagePath,
            OBJ_CASE_INSENSITIVE, NULL, NULL);

        RtlSecureZeroMemory(&iost, sizeof(iost));
        ntStatus = NtCreateFile(&hFile,
            SYNCHRONIZE | FILE_READ_DATA,
            &obja,
            &iost,
            NULL,
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            NULL,
            0);

        if (!NT_SUCCESS(ntStatus))
            break;

        obja.ObjectName = NULL;

        ntStatus = NtCreateSection(&hSection,
            SECTION_MAP_READ,
            &obja,
            NULL,
            PAGE_READONLY,
            SEC_IMAGE_NO_EXECUTE,
            hFile);

        if (!NT_SUCCESS(ntStatus))
            break;

        li.QuadPart = 0;

        ntStatus = NtMapViewOfSection(hSection,
            NtCurrentProcess(),
            BaseAddress,
            0,
            0,
            &li,
            &fileSize,
            ViewShare,
            0,
            PAGE_READONLY);

        if (!NT_SUCCESS(ntStatus))
            break;

    } while (FALSE);

    if (hFile) NtClose(hFile);
    if (hSection) NtClose(hSection);
    return ntStatus;
}

/*
* supQueryNtOsInformation
*
* Purpose:
*
* Map ntoskrnl and query NtBuildNumber value.
*
*/
NTSTATUS supQueryNtOsInformation(
    _Out_ PULONG BuildNumber,
    _Out_opt_ PVOID* MappedNtOs
)
{
    PVOID Ptr;
    NTSTATUS ntStatus;
    PVOID baseAddress = NULL;
    UNICODE_STRING us;

    *BuildNumber = 0;
    if (ARGUMENT_PRESENT(MappedNtOs))
        *MappedNtOs = NULL;

    RtlInitUnicodeStringEx(&us, L"\\systemroot\\system32\\ntoskrnl.exe");
    ntStatus = supMapImageNoExecute(&us, &baseAddress);

    if (NT_SUCCESS(ntStatus)) {

        Ptr = (PVOID)supLdrGetProcAddressEx(baseAddress, "NtBuildNumber");
        if (Ptr) {
            *BuildNumber = (*(PULONG)Ptr & 0xffff);

            if (ARGUMENT_PRESENT(MappedNtOs))
                *MappedNtOs = baseAddress;

            ntStatus = STATUS_SUCCESS;
        }
        else {
            ntStatus = STATUS_INVALID_USER_BUFFER;
        }

    }

    return ntStatus;
}

/*
* supIsFileOwnedByTrustedInstallerSystemOrAdmins
*
* Purpose:
*
* Check whatever file is owner by TI/LocalSystem or Admins group.
*
*/
NTSTATUS supIsFileOwnedByTrustedInstallerSystemOrAdmins(
    _In_ KPROCESSOR_MODE Mode,
    _In_ HANDLE hFile,
    _In_ PUNICODE_STRING pusName
)
{
    NTSTATUS ntStatus;
    ULONG dummy;
    PSID ownerSid;

    union {
        SECURITY_DESCRIPTOR_RELATIVE RelativeSid;
        SECURITY_DESCRIPTOR AbsoluteSid;
        BYTE Buffer[256];
    } OwnerData;

    ntStatus = NtQuerySecurityObject(hFile,
        OWNER_SECURITY_INFORMATION,
        &OwnerData.AbsoluteSid,
        sizeof(OwnerData),
        &dummy);

    if (NT_SUCCESS(ntStatus)) {

        ownerSid = OwnerData.RelativeSid.Control & SE_SELF_RELATIVE ?
            &OwnerData.Buffer[OwnerData.RelativeSid.Owner] : OwnerData.AbsoluteSid.Owner;

        if (RtlEqualSid(ownerSid, &gTrustedInstallerSid))
            return STATUS_SUCCESS;

        if (Mode == UserMode) {

            //
            // Check if this module is in KnownDlls, if so its fucked.
            //

            PWCH p, pp = NULL;
            UNICODE_STRING usBaseFileName, usTypeName;

            p = pusName->Buffer;
            while (*p) {
                if (*p++ == (WCHAR)'\\') {
                    pp = p;
                }
            }

            RtlInitUnicodeString(&usBaseFileName, pp);
            RtlInitUnicodeString(&usTypeName, L"Section");

            BOOL cacheHit = supLookupEntryInKnownDllsCache(&usBaseFileName, &usTypeName);
            if (cacheHit)
                return STATUS_INVALID_IMAGE_HASH;

        }

        //
        // 3rd party code is often not owned by TI, nor LocalSystem, exclude to avoid mass fp's.
        //

        if (RtlEqualSid(ownerSid, &gLocalSystemSid))
            return STATUS_SUCCESS;
        if (RtlEqualSid(ownerSid, &gAdminsGroupSid))
            return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}

/*
* supProcessEntryByProcessId
*
* Purpose:
*
* Find corresponding process entry in a list.
*
*/
PVOID supProcessEntryByProcessId(
    _In_ HANDLE UniqueProcessId,
    _In_ PVOID ProcessList
)
{
    ULONG nextEntryDelta = 0;

    union {
        PSYSTEM_PROCESS_INFORMATION Processes;
        PBYTE ListRef;
    } NativeList;

    NativeList.ListRef = (PBYTE)ProcessList;

    do {

        NativeList.ListRef += nextEntryDelta;

        if (UniqueProcessId == NativeList.Processes->UniqueProcessId) {
            return NativeList.Processes;
        }

        nextEntryDelta = NativeList.Processes->NextEntryDelta;

    } while (nextEntryDelta);

    return NULL;
}

/*
* supThreadToProcessEntry
*
* Purpose:
*
* Find corresponding process entry in a list by thread id.
*
*/
BOOL supThreadToProcessEntry(
    _In_ PVOID ProcessList,
    _In_ HANDLE ThreadId,
    _Out_ PSYSTEM_PROCESS_INFORMATION* ProcessListEntry
)
{
    ULONG nextEntryDelta = 0, i;
    PSYSTEM_PROCESS_INFORMATION entry;

    union {
        PSYSTEM_PROCESS_INFORMATION Process;
        PBYTE ListRef;
    } NativeList;

    *ProcessListEntry = NULL;

    NativeList.ListRef = (PBYTE)ProcessList;

    do {

        NativeList.ListRef += nextEntryDelta;
        entry = NativeList.Process;

        for (i = 0; i < entry->ThreadCount; i++) {
            if (entry->Threads[i].ClientId.UniqueThread == ThreadId) {
                *ProcessListEntry = entry;
                return TRUE;
            }
        }

        nextEntryDelta = NativeList.Process->NextEntryDelta;

    } while (nextEntryDelta);

    return FALSE;
}

/*
* supThreadToProcessHandle
*
* Purpose:
*
* Return process id for given thread.
*
*/
NTSTATUS supThreadToProcessHandle(
    _In_ HANDLE ThreadId,
    _Out_ PHANDLE ProcessId
)
{
    NTSTATUS ntStatus;
    HANDLE hThread = NULL;
    OBJECT_ATTRIBUTES obja;
    CLIENT_ID cid;
    THREAD_BASIC_INFORMATION tbi;
    ULONG returnLength;

    *ProcessId = NULL;

    InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
    cid.UniqueProcess = NULL;
    cid.UniqueThread = ThreadId;

    ntStatus = NtOpenThread(&hThread,
        THREAD_QUERY_LIMITED_INFORMATION, &obja, &cid);

    if (NT_SUCCESS(ntStatus)) {

        ntStatus = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi,
            sizeof(THREAD_BASIC_INFORMATION), &returnLength);

        if (NT_SUCCESS(ntStatus)) {
            *ProcessId = tbi.ClientId.UniqueProcess;
        }

        NtClose(hThread);
    }

    return ntStatus;
}

/*
* supIsProcessRunning
*
* Purpose:
*
* Return TRUE is given process respond.
*
*/
BOOL supIsProcessRunning(
    _In_ HANDLE ProcessId
)
{
    NTSTATUS ntStatus;
    DWORD ret = 0;
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES obja;
    CLIENT_ID cid;

    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = 0;

    InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);

    ntStatus = NtOpenProcess(&hProcess, SYNCHRONIZE, &obja, &cid);
    if (ntStatus == STATUS_ACCESS_DENIED) {
        return TRUE;
    }
    else {
        if (hProcess != NULL) {
            ret = WaitForSingleObject(hProcess, 0);
            NtClose(hProcess);
        }
    }
    return (BOOL)(ret == WAIT_TIMEOUT);
}

/*
* supIsProcessElevated
*
* Purpose:
*
* Returns process elevation state.
*
*/
NTSTATUS supIsProcessElevated(
    _In_ HANDLE ProcessId,
    _Out_ PBOOL Elevated)
{
    NTSTATUS ntStatus;
    ULONG returnedLength;
    HANDLE processHandle = NULL, tokenHandle = NULL;
    TOKEN_ELEVATION tokenInfo;
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES obja;

    if (Elevated) *Elevated = FALSE;

    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = 0;
    InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
    ntStatus = NtOpenProcess(&processHandle,
        MAXIMUM_ALLOWED, &obja, &cid);

    if (NT_SUCCESS(ntStatus)) {

        ntStatus = NtOpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle);
        if (NT_SUCCESS(ntStatus)) {

            tokenInfo.TokenIsElevated = 0;
            ntStatus = NtQueryInformationToken(
                tokenHandle,
                TokenElevation,
                &tokenInfo,
                sizeof(TOKEN_ELEVATION),
                &returnedLength);

            if (NT_SUCCESS(ntStatus)) {

                if (Elevated)
                    *Elevated = (tokenInfo.TokenIsElevated > 0);

            }

            NtClose(tokenHandle);
        }
        NtClose(processHandle);
    }

    return ntStatus;
}

/*
* supCICustomKernelSignersAllowed
*
* Purpose:
*
* Return license state if present (EnterpriseG).
*
*/
NTSTATUS supCICustomKernelSignersAllowed(
    _Out_ PBOOLEAN bAllowed)
{
    NTSTATUS Status;
    ULONG Result = 0, DataSize;
    UNICODE_STRING usLicenseValue;

    *bAllowed = FALSE;

    RtlInitUnicodeString(&usLicenseValue, L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners");
    Status = NtQueryLicenseValue(&usLicenseValue,
        NULL,
        (PVOID)&Result,
        sizeof(DWORD),
        &DataSize);

    if (NT_SUCCESS(Status)) {
        *bAllowed = (Result != 0);
    }
    return Status;
}

/*
* supQuerySystemRangeStart
*
* Purpose:
*
* Return MmSystemRangeStart value.
*
*/
ULONG_PTR supQuerySystemRangeStart(
    VOID
)
{
    NTSTATUS ntStatus;
    ULONG_PTR systemRangeStart = 0;
    ULONG memIO = 0;

    ntStatus = NtQuerySystemInformation(
        SystemRangeStartInformation,
        (PVOID)&systemRangeStart,
        sizeof(ULONG_PTR),
        &memIO);

    if (!NT_SUCCESS(ntStatus)) {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    }
    return systemRangeStart;
}

/*
* supSetMitigationPolicies
*
* Purpose:
*
* Set runtime mitigation policies for process.
*
*/
VOID supSetMitigationPolicies()
{
    PROCESS_MITIGATION_POLICY_INFORMATION policyInfo;

    policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessExtensionPointDisablePolicy;
    policyInfo.ExtensionPointDisablePolicy.Flags = 0;
    policyInfo.ExtensionPointDisablePolicy.DisableExtensionPoints = TRUE;
    NtSetInformationProcess(NtCurrentProcess(),
        ProcessMitigationPolicy,
        &policyInfo,
        sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));

    policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessASLRPolicy;
    policyInfo.ASLRPolicy.Flags = 0;
    policyInfo.ASLRPolicy.EnableHighEntropy = TRUE;
    policyInfo.ASLRPolicy.EnableBottomUpRandomization = TRUE;
    policyInfo.ASLRPolicy.EnableForceRelocateImages = TRUE;
    NtSetInformationProcess(NtCurrentProcess(),
        ProcessMitigationPolicy,
        &policyInfo,
        sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));

    policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy;
    policyInfo.SignaturePolicy.Flags = 0;
    policyInfo.SignaturePolicy.MicrosoftSignedOnly = TRUE;
    policyInfo.SignaturePolicy.MitigationOptIn = 1;
    NtSetInformationProcess(NtCurrentProcess(),
        ProcessMitigationPolicy,
        &policyInfo,
        sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));

    policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessImageLoadPolicy;
    policyInfo.ImageLoadPolicy.Flags = 0;
    policyInfo.ImageLoadPolicy.PreferSystem32Images = TRUE;
    policyInfo.ImageLoadPolicy.NoRemoteImages = TRUE;
    policyInfo.ImageLoadPolicy.NoLowMandatoryLabelImages = TRUE;
    NtSetInformationProcess(NtCurrentProcess(),
        ProcessMitigationPolicy,
        &policyInfo,
        sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));

    policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessFontDisablePolicy;
    policyInfo.FontDisablePolicy.Flags = 0;
    policyInfo.FontDisablePolicy.DisableNonSystemFonts = TRUE;
    NtSetInformationProcess(NtCurrentProcess(),
        ProcessMitigationPolicy,
        &policyInfo,
        sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));
}
