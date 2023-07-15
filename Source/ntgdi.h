/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2023
*  Translated from Microsoft sources/debugger or mentioned elsewhere.
*
*  TITLE:       NTGDI.H
*
*  VERSION:     1.07
*
*  DATE:        15 Jun 2023
*
*  Common header file for the NtGdi API functions and definitions.
*
*  Only projects required API/definitions.
*
*  Depends on:    Windows.h
*                 NtStatus.h
*                 NtOs.h
*
*  Include:       Windows.h
*                 NtStatus.h
*                 NtOs.h
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#pragma warning(push)
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 4214) // nonstandard extension used : bit field types other than int

#ifndef NTGDI_RTL
#define NTGDI_RTL



#define GDI_HANDLE_TO_INDEX(h) (DWORD)((ULONG_PTR)h & 0x0000ffff)

#define DEF_TYPE            0
#define DC_TYPE             1
#define UNUSED1_TYPE        2   // Unused
#define UNUSED2_TYPE        3   // Unused
#define RGN_TYPE            4
#define SURF_TYPE           5
#define CLIENTOBJ_TYPE      6
#define PATH_TYPE           7
#define PAL_TYPE            8
#define ICMLCS_TYPE         9
#define LFONT_TYPE          10
#define RFONT_TYPE          11
#define PFE_TYPE            12
#define PFT_TYPE            13
#define ICMCXF_TYPE         14
#define SPRITE_TYPE         15
#define BRUSH_TYPE          16
#define UMPD_TYPE           17
#define UNUSED4_TYPE        18  // Unused
#define SPACE_TYPE          19
#define UNUSED5_TYPE        20  // Unused
#define META_TYPE           21
#define EFSTATE_TYPE        22
#define UNUSED6_TYPE        23  // Unused
#define UNUSED7_TYPE        24  // Unused
#define UNUSED8_TYPE        25  // Unused
#define UNUSED9_TYPE        26  // Unused
#define UNUSED10_TYPE       27  // Unused
#define DRVOBJ_TYPE         28
#define UNUSED11_TYPE       29  // Unused
#define SPOOL_TYPE          30
#define MAX_TYPE            30 

#define GDI_INDEX_BITS         16
#define GDI_TYPE_BITS           5
#define GDI_ALTTYPE_BITS        2
#define GDI_STOCK_BITS          1
#define GDI_UNIQUE_BITS         8

#define GDI_TYPE_SHIFT          (GDI_INDEX_BITS)
#define GDI_ALTTYPE_SHIFT       (GDI_TYPE_SHIFT + GDI_TYPE_BITS)
#define GDI_STOCK_SHIFT         (GDI_ALTTYPE_SHIFT + GDI_ALTTYPE_BITS)

#define ALTTYPE1            (1 << ALTTYPE_SHIFT)
#define ALTTYPE2            (2 << ALTTYPE_SHIFT)
#define ALTTYPE3            (3 << ALTTYPE_SHIFT)

#define LO_BRUSH_TYPE       (BRUSH_TYPE     << GDI_TYPE_SHIFT)
#define LO_DC_TYPE          (DC_TYPE        << GDI_TYPE_SHIFT)
#define LO_BITMAP_TYPE      (SURF_TYPE      << GDI_TYPE_SHIFT)
#define LO_PALETTE_TYPE     (PAL_TYPE       << GDI_TYPE_SHIFT)
#define LO_FONT_TYPE        (LFONT_TYPE     << GDI_TYPE_SHIFT)
#define LO_REGION_TYPE      (RGN_TYPE       << GDI_TYPE_SHIFT)
#define LO_ICMLCS_TYPE      (ICMLCS_TYPE    << GDI_TYPE_SHIFT)
#define LO_CLIENTOBJ_TYPE   (CLIENTOBJ_TYPE << GDI_TYPE_SHIFT)

#define LO_ALTDC_TYPE       (LO_DC_TYPE        | ALTTYPE1)
#define LO_PEN_TYPE         (LO_BRUSH_TYPE     | ALTTYPE1)
#define LO_EXTPEN_TYPE      (LO_BRUSH_TYPE     | ALTTYPE2)
#define LO_DIBSECTION_TYPE  (LO_BITMAP_TYPE    | ALTTYPE1)
#define LO_METAFILE16_TYPE  (LO_CLIENTOBJ_TYPE | ALTTYPE1)
#define LO_METAFILE_TYPE    (LO_CLIENTOBJ_TYPE | ALTTYPE2)
#define LO_METADC16_TYPE    (LO_CLIENTOBJ_TYPE | ALTTYPE3)

typedef ULONG W32PID;
typedef UCHAR OBJTYPE;

typedef union _EINFO {
    PVOID pobj;
    PVOID hFree;
} EINFO;

#define OBJECT_OWNER_ERROR   (0x80000022)
#define OBJECT_OWNER_PUBLIC  (0x00000000)
#define OBJECT_OWNER_CURRENT (0x80000002)
#define OBJECT_OWNER_NONE    (0x80000012)

typedef struct _OBJECTOWNER_S {
    ULONG Lock : 1;
    W32PID Pid_Shifted : 31;
}OBJECTOWNER_S, * POBJECTOWNER_S;

typedef union _OBJECTOWNER {
    OBJECTOWNER_S Share;
    ULONG ulObj;
}OBJECTOWNER, * POBJECTOWNER;

typedef struct _GDI_HANDLE_ENTRY {
    EINFO einfo;
    OBJECTOWNER ObjectOwner;
    USHORT FullUnique;
    UCHAR Objt;
    UCHAR Flags;
    PVOID pUser;
} GDI_HANDLE_ENTRY, * PGDI_HANDLE_ENTRY;

#define LOCK_MASK 0x00000001
#define PID_MASK  0xfffffffe

#define PID_BITS 0xfffffffc
#define OBJECTOWNER_PID(ObjectOwner) \
    ((W32PID) ((ObjectOwner).ulObj & PID_MASK))

// entry.Flags flags

#define HMGR_ENTRY_UNDELETABLE      0x0001
#define HMGR_ENTRY_LAZY_DEL         0x0002
#define HMGR_ENTRY_INVALID_VIS      0x0004
#define HMGR_ENTRY_LOOKASIDE_ALLOC  0x0010

#define GDI_MAX_HANDLE_COUNT_V1 0x4000
#define GDI_MAX_HANDLE_COUNT_V2 0xFFFF
#define GDI_MAX_HANDLE_COUNT GDI_MAX_HANDLE_COUNT_V2

typedef struct _GDI_SHARED_MEMORY {
    GDI_HANDLE_ENTRY aentryHmgr[GDI_MAX_HANDLE_COUNT];
    //incomplete
} GDI_SHARED_MEMORY, * PGDI_SHARED_MEMORY;

#pragma warning(pop)

#endif NTGDI_RTL
