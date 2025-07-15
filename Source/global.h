/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023 - 2025
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.10
*
*  DATE:        11 Jul 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#if !defined UNICODE
#error ANSI build is not supported
#endif

#undef VERBOSE_OUTPUT

#define MAX_TEXT_LENGTH 256

//
// Ignored warnings
//
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4091) // 'typedef ': ignored on left of '%s' when no variable is declared
#pragma warning(disable: 4201) // nameless struct/union
#pragma warning(disable: 26812) // Prefer 'enum class' over 'enum'

#if defined (_MSC_VER)
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1920)
#pragma comment(linker,"/merge:_RDATA=.rdata")
#endif
#endif

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

#if defined(__cplusplus)
#include <malloc.h>
#endif

#include <Windows.h>
#include <Windowsx.h>
#include <commctrl.h>
#include <Uxtheme.h>
#include <ShlObj.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <ntstatus.h>
#include <intrin.h>
#include <wbemidl.h> 
#include <oleauto.h>
#include <wintrust.h>
#include <mscat.h>
#include <Softpub.h>

//
// Main window listview.
//
extern HWND hwndList;
extern HWND hwndStatusBar;
extern ULONG g_cAnomalies;
extern volatile LONG gbScanRunning;

#include "consts.h"
#include "ntos.h"
#include "ntbuilds.h"
#include "ntuser.h"
#include "ntgdi.h"
#include "sup.h"
#include "ntproto.h"
#include "resource.h"
#include "probes.h"

#if defined(__cplusplus)
extern "C" {
#endif

#include "minirtl/minirtl.h"
#include "minirtl/rtltypes.h"
#include "hde/hde64.h"

#ifdef __cplusplus
}
#endif

#define PROGRAM_NAME L"WubbabooMark"
#define SK_VERSION_MAJOR 1
#define SK_VERSION_MINOR 1
#define SK_VERSION_BUILD 2507 

#define PUSH_DISABLE_WARNING(Warning) \
  __pragma(warning(push)) \
  __pragma(warning(disable : Warning))

#define POP_DISABLE_WARNING(Warning) \
  __pragma(warning(pop))

#if defined(__cplusplus)
extern "C" {
#endif

    NTSTATUS SkiDirectSystemCall();
    NTSTATUS SkiIndirectSystemCall();

    extern DWORD KiSystemCallNumber;
    extern ULONG_PTR KiSystemCallAddress;

#ifdef __cplusplus
}
#endif

extern HANDLE gProbeWait;
