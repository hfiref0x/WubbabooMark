/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       MAIN.CPP
*
*  VERSION:     1.00
*
*  DATE:        01 Jul 2023
*
*  CodeName:    Skilla
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#define OEMRESOURCE
#include "global.h"

#define CLASSNAME L"WubbabooMarkClass"

// low area height plus the borders
#define BORDERHEIGHT 8
#define BORDRERSPACE 4

//
// Global variables.
//
HANDLE gProbeWait = NULL;
ATOM mainClass = 0;
HWND hwndList = NULL;
HWND hwndStatusBar = NULL;
HINSTANCE thisInstance = NULL;
PROBE_STARTUP_INFO gProbeParams;

/*
* InsertRunAsMainMenuEntry
*
* Purpose:
*
* Insert run as admin/local system menu entry.
*
*/
VOID InsertRunAsMainMenuEntry(
    _In_ HWND hwnd
)
{
    HMENU hMenu;
    SHSTOCKICONINFO sii;

    WCHAR szText[MAX_TEXT_LENGTH];

    if (!supUserIsFullAdmin()) {
        hMenu = GetSubMenu(GetMenu(hwnd), 0);
        InsertMenu(hMenu, 0, MF_BYPOSITION, ID_FILE_RUNASADMIN, TEXT("R&un as Administrator"));
        InsertMenu(hMenu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);

        RtlSecureZeroMemory(&sii, sizeof(sii));
        sii.cbSize = sizeof(sii);
        if (SHGetStockIconInfo(SIID_SHIELD, SHGSI_ICON | SHGFI_SMALLICON, &sii) == S_OK) {
            MENUITEMINFO mii;
            RtlSecureZeroMemory(&mii, sizeof(mii));
            mii.cbSize = sizeof(mii);
            mii.fMask = MIIM_BITMAP | MIIM_DATA;
            mii.hbmpItem = HBMMENU_CALLBACK;
            mii.dwItemData = (ULONG_PTR)sii.hIcon;
            SetMenuItemInfo(hMenu, ID_FILE_RUNASADMIN, FALSE, &mii);
        }
        _strcpy(szText, PROGRAM_NAME);
    }
    else {
        StringCchPrintf(szText,
            RTL_NUMBER_OF(szText),
            TEXT("%ws (Administrator)"),
            PROGRAM_NAME);
    }
    SetWindowText(hwnd, szText);
}

VOID MainWindowOnResize(
    _In_ HWND hwndDlg
)
{
    RECT r, szr;

    RtlSecureZeroMemory(&r, sizeof(RECT));
    RtlSecureZeroMemory(&szr, sizeof(RECT));

    GetClientRect(hwndDlg, &r);
    GetClientRect(hwndStatusBar, &szr);

    SendMessage(hwndStatusBar, WM_SIZE, 0, 0);

    SetWindowPos(hwndList, NULL, BORDRERSPACE, BORDRERSPACE,
        r.right - BORDERHEIGHT,
        r.bottom - szr.bottom - BORDERHEIGHT,
        SWP_NOZORDER);
}

VOID SettingsReadWrite(
    _In_ HWND hwndDlg,
    _In_ BOOL bWrite)
{
    struct SettingsControlMap {
        ULONG FlagControlId;
        ULONG FlagValue;
    };

    SettingsControlMap ctrlMap[] = {
        { IDC_PROBES1, PROBE_FLAGS_COMMON_CHECKS },
        { IDC_PROBES2, PROBE_FLAGS_VERIFY_PEBLDR },
        { IDC_PROBES3, PROBE_FLAGS_VERIFY_LOADED_DRIVERS },
        { IDC_PROBES4, PROBE_FLAGS_CHECK_DEVICE_OBJECTS },
        { IDC_PROBES5, PROBE_FLAGS_VERIFY_WINVER },
        { IDC_PROBES6, PROBE_FLAGS_VALIDATE_PROCLIST },
        { IDC_PROBES7, PROBE_FLAGS_VALIDATE_THREADLIST },
        { IDC_PROBES8, PROBE_FLAGS_VALIDATE_NTDLLCOPIES },
        { IDC_PROBES9, PROBE_FLAGS_STACKWALK },
        { IDC_PROBES10, PROBE_FLAGS_WSSETWALK },
        { IDC_PROBES11, PROBE_FLAGS_WSSETWATCH },
        { IDC_PROBES12, PROBE_FLAGS_HANDLETRACING },
        { IDC_PROBES13, PROBE_FLAGS_CHECK_NTOS_SYSCALLS },
        { IDC_PROBES14, PROBE_FLAGS_CHECK_WIN32K_SYSCALLS },
        { IDC_PROBES15, PROBE_FLAGS_CHECK_DEBUG },
        { IDC_PROBES16, PROBE_FLAGS_CHECK_HANDLES },
        { IDC_PROBES17, PROBE_FLAGS_WALK_USERHADLETABLE },
        { IDC_PROBES18, PROBE_FLAGS_WALK_GDISHAREDHADLETABLE },
        { IDC_PROBES19, PROBE_FLAGS_CHECK_BCD },
        { IDC_PROBES20, PROBE_FLAGS_CHECK_PROCESS_MEMORY }
    };

    PROBE_SETTINGS probeSettings;
    WCHAR szErrorMsg[MAX_TEXT_LENGTH];

    if (bWrite) {

        probeSettings.Flags = 0;

        for (ULONG i = 0; i < RTL_NUMBER_OF(ctrlMap); i++) {
            if (IsDlgButtonChecked(hwndDlg, ctrlMap[i].FlagControlId)) {
                probeSettings.Flags |= ctrlMap[i].FlagValue;
            }
        }
      
        if (!supWriteConfiguration(&probeSettings)) {
                       
            StringCchPrintf(szErrorMsg,
                RTL_NUMBER_OF(szErrorMsg),
                TEXT("There is an error with code %lu while saving probes settings"),
                GetLastError());

            MessageBox(hwndDlg, szErrorMsg, PROGRAM_NAME, MB_ICONINFORMATION);
        }
    }
    else {

        if (!supReadConfiguration(&probeSettings)) {

            StringCchPrintf(szErrorMsg,
                RTL_NUMBER_OF(szErrorMsg),
                TEXT("There is an error with code %lu while reading probes settings, default will be used"),
                GetLastError());

            MessageBox(hwndDlg, szErrorMsg, PROGRAM_NAME, MB_ICONINFORMATION);
        }

        for (ULONG i = 0; i < RTL_NUMBER_OF(ctrlMap); i++) {
            CheckDlgButton(hwndDlg, ctrlMap[i].FlagControlId,
                (probeSettings.Flags & ctrlMap[i].FlagValue) ?
                BST_CHECKED : BST_UNCHECKED);
        }
    }
}

INT_PTR CALLBACK SettingsDialogProc(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (uMsg) {

    case WM_INITDIALOG:
        SettingsReadWrite(hwndDlg, FALSE);
        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case IDCANCEL:
            return EndDialog(hwndDlg, ERROR_CANCELLED);
        case IDOK:
            SettingsReadWrite(hwndDlg, TRUE);
            return EndDialog(hwndDlg, ERROR_SUCCESS);
        }

    }
    return 0;
}

INT_PTR CALLBACK AboutDialogProc(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    LITEM item;
    PNMLINK pNMLink;

    switch (uMsg) {

    case WM_NOTIFY:

        switch (((LPNMHDR)lParam)->code) {
        case NM_CLICK:
        case NM_RETURN:

            pNMLink = (PNMLINK)lParam;
            item = pNMLink->item;
            if ((((LPNMHDR)lParam)->hwndFrom == GetDlgItem(hwndDlg, IDC_SYSLINK))
                && (item.iLink == 0))
            {
                supShellExecInExplorerProcess(item.szUrl, NULL);
            }

            break;
        }

        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case IDCANCEL:
        case IDOK:
            return EndDialog(hwndDlg, S_OK);
        }

    }
    return 0;
}

VOID MainWindowSetViewReady()
{
    HIMAGELIST hImageList;
    LVCOLUMNS_DATA columnData[] =
    {
        { (LPWSTR)TEXT("Event"), 360, LVCFMT_LEFT,  I_IMAGENONE },
        { (LPWSTR)TEXT("Description"), 200, LVCFMT_LEFT, I_IMAGENONE },
        { (LPWSTR)TEXT("Anomaly Type"), 150, LVCFMT_LEFT, I_IMAGENONE }
    };

    hImageList = supLoadImageList(thisInstance);

    supSetListViewSettings(hwndList,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
        TRUE,
        hImageList,
        LVSIL_SMALL);

    supAddLVColumnsFromArray(
        hwndList,
        columnData,
        RTL_NUMBER_OF(columnData));

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
}

LRESULT CALLBACK MainWindowProc(
    _In_ HWND hwnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    switch (uMsg) {

    case WM_MEASUREITEM:

        LPMEASUREITEMSTRUCT pms;

        pms = (LPMEASUREITEMSTRUCT)lParam;
        if (pms && pms->CtlType == ODT_MENU) {
            pms->itemWidth = 16;
            pms->itemHeight = 16;
        }
        break;

    case WM_DRAWITEM:

        LPDRAWITEMSTRUCT pds;

        pds = (LPDRAWITEMSTRUCT)lParam;
        if (pds && pds->CtlType == ODT_MENU) {
            DrawIconEx(pds->hDC, pds->rcItem.left - 15,
                pds->rcItem.top,
                (HICON)pds->itemData,
                16, 16, 0, NULL, DI_NORMAL);
        }
        break;

    case WM_CLOSE:
        PostQuitMessage(0);
        break;

    case WM_SIZE:
        MainWindowOnResize(hwnd);
        break;

    case WM_COMMAND:
        switch (GET_WM_COMMAND_ID(wParam, lParam)) {

        case ID_FILE_SCAN:
            gProbeParams.IsFirstRun = FALSE;
            gProbeParams.MainWindow = hwnd;
            supReadConfiguration(&gProbeParams.Settings);
            SkStartProbe(&gProbeParams);
            break;

        case ID_HELP_ABOUT:
            DialogBoxParam(thisInstance, MAKEINTRESOURCE(IDD_ABOUT), hwnd, AboutDialogProc, 0);
            break;

        case IDCANCEL:
        case ID_FILE_EXIT:
            SendMessage(hwnd, WM_CLOSE, 0, 0);
            break;

        case ID_PROBES_SAVETOFILE:
            supListViewExportToFile(TEXT("probes.csv"), hwnd, hwndList);
            break;

        case ID_PROBES_SETTINGS:
            DialogBoxParam(thisInstance, MAKEINTRESOURCE(IDD_SETTINGS), hwnd, SettingsDialogProc, 0);
            break;

        case ID_FILE_RUNASADMIN:
            supRunAsAdmin();
            break;

        }
        break;

    case WM_ACTIVATE:
    case WM_SETFOCUS:
        SetFocus(hwndList);
        break;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

DWORD RunMainDialog()
{
    HWND hwndMain;
    WNDCLASSEX wndClass;
    BOOL bResult;
    MSG message;
    INITCOMMONCONTROLSEX iccx;

    thisInstance = GetModuleHandle(NULL);

    gProbeWait = CreateMutex(NULL, FALSE, NULL);
    if (gProbeWait == NULL)
        return GetLastError();

    iccx.dwSize = sizeof(iccx);
    iccx.dwICC = ICC_LISTVIEW_CLASSES | ICC_LINK_CLASS;
    if (!InitCommonControlsEx(&iccx))
        return GetLastError();

    RtlSecureZeroMemory(&wndClass, sizeof(WNDCLASSEX));
    wndClass.cbSize = sizeof(WNDCLASSEX);
    wndClass.style = 0;
    wndClass.lpfnWndProc = &MainWindowProc;
    wndClass.cbClsExtra = 0;
    wndClass.cbWndExtra = DLGWINDOWEXTRA;
    wndClass.hInstance = thisInstance;

    wndClass.hIcon = (HICON)LoadImage(
        thisInstance,
        MAKEINTRESOURCE(IDI_ICON_MAIN),
        IMAGE_ICON,
        0,
        0,
        LR_SHARED);

    wndClass.hCursor = (HCURSOR)LoadImage(
        NULL,
        MAKEINTRESOURCE(OCR_NORMAL),
        IMAGE_CURSOR,
        0,
        0,
        LR_SHARED);

    wndClass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wndClass.lpszMenuName = NULL;
    wndClass.lpszClassName = CLASSNAME;
    wndClass.hIconSm = 0;

    mainClass = RegisterClassEx(&wndClass);
    if (mainClass == 0)
        return GetLastError();

    hwndMain = CreateDialogParam(thisInstance,
        MAKEINTRESOURCE(IDD_MAINDIALOG), NULL, MainWindowProc, 0);

    if (hwndMain) {

        hwndList = GetDlgItem(hwndMain, IDC_LIST);
        hwndStatusBar = GetDlgItem(hwndMain, IDC_STATUSBAR);
        MainWindowSetViewReady();

        ShowWindow(hwndMain, SW_SHOW);
        SendMessage(hwndMain, WM_SIZE, 0, 0);
        UpdateWindow(hwndMain);
        InsertRunAsMainMenuEntry(hwndMain);

        gProbeParams.IsFirstRun = TRUE;
        gProbeParams.MainWindow = hwndMain;
        supReadConfiguration(&gProbeParams.Settings);
        SkStartProbe(&gProbeParams);

        do {

            bResult = GetMessage(&message, NULL, 0, 0);
            if (bResult == -1)
                break;

            if (!IsDialogMessage(hwndMain, &message)) {
                TranslateMessage(&message);
                DispatchMessage(&message);
            }

        } while (bResult != 0);

    }
    else {
        return GetLastError();
    }

    UnregisterClass(CLASSNAME, thisInstance);

    return 0;
}

INT EntryPoint()
{
    NTSTATUS ntStatus;
    DWORD exitProcessCode;

    RtlSetUnhandledExceptionFilter(supUnhandledExceptionFilter);
    HeapSetInformation(NtCurrentPeb()->ProcessHeap, HeapEnableTerminationOnCorruption, NULL, 0);
    supSetMitigationPolicies();
    supCacheKnownDllsEntries();       
    ntStatus = supInitializeKnownSids();
    if (!NT_SUCCESS(ntStatus)) {
        exitProcessCode = ntStatus;
    }
    else {
        exitProcessCode = RunMainDialog();
    }
    return exitProcessCode;
}

#if !defined(__cplusplus)
#pragma comment(linker, "/ENTRY:main")
void main()
{
    __security_init_cookie();
    ExitProcess(EntryPoint());

}
#else
#pragma comment(linker, "/ENTRY:WinMain")
int CALLBACK WinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR     lpCmdLine,
    _In_ int       nCmdShow
)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    ExitProcess(EntryPoint());
}
#endif
