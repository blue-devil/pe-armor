/*
 * _______________________________________________________________________
 *|  ______ __          ,.'   __.'.__  .   ______               ___       |
 *| |      |  |         /b`  '-.   .-'  d\|      ;             |   |      |
 *| |   __ |  |        .5h     /.'.\    =5|   _   \            |   |      |
 *| |.  1 \|  |        (0=h    '   '    =C)   1\   \        .--:.  |      |
 *| |   1_/|  |        ?3==,          .==7|   | \   \       |__|   |      |
 *| |.     | .-- -.-----{=`==oo____oo==`=}|   |  |.----.-- -.--:.  |      |
 *| |.  __ | |  V |  ^__|'"o58888888888,; |.  |  ||  ^_|  V |  |.  |      |
 *| |:  1 \|_|____|_____| `?88P^\,?88^\P  |.  | / |____|\___|__|:  |___   |
 *| |:  1_/   /            C8?\__d88\_/'  |:  1/   / .         |:  1   |  |
 *| |::.. .  /             `8o8888/\88P   |::.. . /            |::.. . |  |
 *| `-------'               '7oo88oo8P    `------'             `-------'  |
 *|                     Cooo##~\/\/\/~====>        github.com/blue-devil  |
 *|                                                 gitlab.com/bluedevil  |
 *| Freedom doesn't come from second-hand thoughts.                       |
 *|_______________________________________________________________________|
 *| @author   : Blue DeviL                                                |
 *| @tester   : ErrorInside                                               |
 *| @IDE      : Vi iMproved                                               |
 *| @template : Blue DeviL                                                |
 *| @date     : 30/10/2026                                                |
 *| @license  : SCT-PL                                                    |
 *|_______________________________________________________________________|
 *|                                                                       |
 *|                            PE-Armor vx.xy                             |
 *|                          Developers' Edition                          |
 *\_______________________________________________________________________/
 *
 * Reverse-engineered recreation of REPUBLIC's modified PE-Armor packer
 * (original v0.46 by hying[CCG], masm32; vx.xx is an MSVC C++ rebuild).
 *
 * Packed-file format (matches the original byte-for-byte in structure):
 *
 *   + all section VirtualSizes rounded up to SectionAlignment
 *   + sections named {.text,.data,.rdata,CODE,DATA,.reloc} (and not hosting
 *     the import/export directory) are aPLib-compressed in place; all-zero
 *     sections lose their raw data; everything else is stored raw
 *   + packed sections get RWX characteristics; all names randomized except
 *     the resource section
 *   + a TLS directory rewrite routes the loader's TLS callbacks through the
 *     stub trampoline before the original entry point runs
 *   + the appended .stub section holds:
 *       [0x000] pushad/call entry + 3-function KERNEL32 import block
 *       [0x0AC] live TLS directory, [0x0C4] original TLS directory copy
 *       [0x0DC] callback array -> [0x0E4] TLS callback trampoline
 *       [0x147] first stage: XOR-decrypt + aP-depack the second stage,
 *               VirtualAlloc(PAGE_EXECUTE_READWRITE), jump into it
 *       [0x27C] XOR-encrypted aPLib stream of the second stage
 *   + the second stage (0x7038-byte template) carries the original entry
 *     point, feature flags, per-section restore records and the custom
 *     obfuscated import table, and restores everything at load time
 *
 * Options live in %APPDATA%\pediy.ini, section [ProtSet].
 * Build: build.bat (msys64 mingw32, aplib)
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <commdlg.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "resource.h"
#include "aplib.h"
#include "stub_vx.h"

#define APP_INI "pediy.ini"
#define PROGRESS_CTRL 3004
#define PBM_SETPOS_ 0x402u

/* option flags */
static int g_Align200, g_ProtImp, g_PackRes, g_SaveSData, g_MergeSections,
    g_ClsSecName, g_NoReloc, g_CreateBak, g_DelShare, g_AnalyzeImmunity,
    g_MemoryShield, g_BlacklistScan, g_HeaderShield, g_StripDebug;

static int g_Busy;
static BYTE *g_image;
static DWORD g_imageSize;
static DWORD g_peOffset;
static PIMAGE_NT_HEADERS g_nt;
static PIMAGE_SECTION_HEADER g_sec;
static DWORD g_numSec;
static DWORD g_fileAlign, g_secAlign;
static HWND g_hProgress;

static char g_fileName[MAX_PATH];
static HINSTANCE g_hInst;
static HWND g_hMain, g_hChildMain, g_hChildOpt, g_hTab;
static char *g_logBuf;

#pragma pack(push, 1)
typedef struct { DWORD vsize, rva, packSize; } PACKREC;
#pragma pack(pop)
static PACKREC g_recs[64];
static int g_recCount;

static BYTE *g_impBuf;
static DWORD g_impSize;

/* ------------------------------------------------------------------ */
static void AddLine(HWND hDlg, const char *line)
{
    if (!g_logBuf) return;
    if (hDlg && GetDlgItemTextA(hDlg, IDC_LOG, g_logBuf, 0x10000))
        strcat(g_logBuf, "\r\n");
    else
        g_logBuf[0] = 0;
    strcat(g_logBuf, line);
    if (hDlg) {
        int n;
        SendDlgItemMessageA(hDlg, IDC_LOG, WM_SETTEXT, 0, (LPARAM)g_logBuf);
        n = (int)SendDlgItemMessageA(hDlg, IDC_LOG, EM_GETLINECOUNT, 0, 0);
        SendDlgItemMessageA(hDlg, IDC_LOG, EM_LINESCROLL, 0, n);
    } else {
        printf("%s\n", line);
    }
}

static DWORD AlignUp(DWORD v, DWORD a)
{
    return a * ((v + a - 1) / a);
}

static void *ImgPtr(DWORD rva)
{
    if (rva >= g_imageSize) return NULL;
    return g_image + rva;
}

static DWORD StrLenA(const char *s) { DWORD n = 0; while (s[n]) n++; return n; }

/* ------------------------------------------------------------------ */
static void IniPath(char *path)
{
    char appdata[MAX_PATH];
    if (GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH))
        wsprintfA(path, "%s\\%s", appdata, APP_INI);
    else
        lstrcpyA(path, APP_INI);
}

static void ReadIni(void)
{
    char path[MAX_PATH * 2];
    IniPath(path);
#define RD(var, key, def) (var) = GetPrivateProfileIntA("ProtSet", key, def, path)
    RD(g_Align200, "IsFileAlignment200", 0);
    RD(g_ProtImp, "IsProtImpTable", 0);
    RD(g_PackRes, "isPackRes", 0);
    /* original quirk: the ini loader stores IsSaveSData into the PackRes
       flag (dword_41A048) and never initializes dword_41A04C; the SaveSData
       flag only becomes live from the Options checkbox on tab switch */
    if (GetPrivateProfileIntA("ProtSet", "IsSaveSData", 0, path) == 1)
        g_PackRes = 1;
    RD(g_MergeSections, "IsMergeSection", 0);
    RD(g_ClsSecName, "IsClsSecName", 0);
    RD(g_NoReloc, "IsNoRelocation", 0);
    RD(g_CreateBak, "IsCreateBak", 0);
    RD(g_DelShare, "IsDelShare", 0);
    RD(g_AnalyzeImmunity, "IsAnalyzeImmunity", 1);
    RD(g_MemoryShield, "IsMemoryShield", 1);
    RD(g_BlacklistScan, "IsBlacklistScan", 0);
    RD(g_HeaderShield, "IsHeaderShield", 0);
    RD(g_StripDebug, "StripDebug", 1);
#undef RD
}

static void LoadOptionsUI(HWND hDlg)
{
#define CK(var, id) CheckDlgButton(hDlg, id, (var) ? BST_CHECKED : BST_UNCHECKED)
    CK(g_Align200, IDC_FA200);
    CK(g_ProtImp, IDC_APIPROT);
    CK(g_PackRes, IDC_PACKRES);
    CK(g_SaveSData, IDC_SDATA);
    CK(g_MergeSections, IDC_MERGESECTION);
    CK(g_ClsSecName, IDC_CLSSECNAME);
    CK(g_NoReloc, IDC_NOREL);
    CK(g_CreateBak, IDC_CREATEBAK);
    CK(g_DelShare, IDC_DELSHARE);
    CK(g_AnalyzeImmunity, IDC_ANALYZEIMMUNITY);
    CK(g_MemoryShield, IDC_MEMORYSHIELD);
    CK(g_BlacklistScan, IDC_BLACKLISTSCAN);
    CK(g_HeaderShield, IDC_HEADERSHIELD);
    CK(g_StripDebug, IDC_STRIPDEBUG);
#undef CK
}

static void SaveOptionsUI(HWND hDlg)
{
    char path[MAX_PATH * 2], val[16];
    IniPath(path);
#define SV(var, key) do { wsprintfA(val, "%d", (var)); WritePrivateProfileStringA("ProtSet", key, val, path); } while (0)
    SV(g_Align200, "IsFileAlignment200");
    SV(g_ProtImp, "IsProtImpTable");
    SV(g_PackRes, "isPackRes");
    SV(g_SaveSData, "IsSaveSData");
    SV(g_MergeSections, "IsMergeSection");
    SV(g_ClsSecName, "IsClsSecName");
    SV(g_NoReloc, "IsNoRelocation");
    SV(g_CreateBak, "IsCreateBak");
    SV(g_DelShare, "IsDelShare");
    SV(g_AnalyzeImmunity, "IsAnalyzeImmunity");
    SV(g_MemoryShield, "IsMemoryShield");
    SV(g_BlacklistScan, "IsBlacklistScan");
    SV(g_HeaderShield, "IsHeaderShield");
    SV(g_StripDebug, "StripDebug");
#undef SV
}

static void OptionsFromUI(HWND hDlg)
{
#define GT(var, id) (var) = (SendDlgItemMessageA(hDlg, id, BM_GETCHECK, 0, 0) == BST_CHECKED)
    GT(g_Align200, IDC_FA200);
    GT(g_ProtImp, IDC_APIPROT);
    GT(g_PackRes, IDC_PACKRES);
    GT(g_SaveSData, IDC_SDATA);
    GT(g_MergeSections, IDC_MERGESECTION);
    GT(g_ClsSecName, IDC_CLSSECNAME);
    GT(g_NoReloc, IDC_NOREL);
    GT(g_CreateBak, IDC_CREATEBAK);
    GT(g_DelShare, IDC_DELSHARE);
    GT(g_AnalyzeImmunity, IDC_ANALYZEIMMUNITY);
    GT(g_MemoryShield, IDC_MEMORYSHIELD);
    GT(g_BlacklistScan, IDC_BLACKLISTSCAN);
    GT(g_HeaderShield, IDC_HEADERSHIELD);
    GT(g_StripDebug, IDC_STRIPDEBUG);
#undef GT
}

/* ------------------------------------------------------------------ */
static int CheckTarget(HWND hDlg)
{
    HANDLE h, map;
    void *view;
    BYTE *base;
    DWORD peoff;
    PIMAGE_NT_HEADERS nt;
    h = CreateFileA(g_fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE || GetFileSize(h, NULL) == INVALID_FILE_SIZE) {
        AddLine(hDlg, "Error! Failed to open file!");
        return 0;
    }
    map = CreateFileMappingA(h, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!map) { CloseHandle(h); AddLine(hDlg, "Error! Failed to open file!"); return 0; }
    view = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if (!view) { CloseHandle(map); CloseHandle(h); AddLine(hDlg, "Error! Failed to open file!"); return 0; }
    base = (BYTE *)view;
    peoff = *(DWORD *)(base + 0x3C);
    nt = (PIMAGE_NT_HEADERS)(base + peoff);
    if (*(WORD *)base != 0x5A4D || nt->Signature != 0x00004550) {
        AddLine(hDlg, "Error! Not an executable file!");
        UnmapViewOfFile(view); CloseHandle(map); CloseHandle(h);
        return 0;
    }
    if (nt->FileHeader.Characteristics == 1 ||
        nt->OptionalHeader.AddressOfEntryPoint >
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
        AddLine(hDlg, "File may already be packed, aborting!");
        UnmapViewOfFile(view); CloseHandle(map); CloseHandle(h);
        return 0;
    }
    AddLine(hDlg, (nt->FileHeader.Characteristics & IMAGE_FILE_DLL)
        ? "It is a PE-DLL file, can be packed."
        : "It is a Portable executable-EXE file, can be packed.");
    UnmapViewOfFile(view);
    CloseHandle(map);
    CloseHandle(h);
    return 1;
}

/* ------------------------------------------------------------------ */
/* custom obfuscated import table (matches the original blob format)   */
static int BuildImpTable(HWND hDlg)
{
    DWORD dirRva = g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR *desc;
    BYTE *out, *p;
    out = (BYTE *)calloc(0xA0000, 1);
    if (!out) { AddLine(hDlg, "Error! Out of memory."); return 0; }
    p = out;
    desc = (IMAGE_IMPORT_DESCRIPTOR *)ImgPtr(dirRva);
    if (!desc || !desc->Name || !ImgPtr(desc->Name)) {
        AddLine(hDlg, "Insufficient memory or no import table in file.");
        free(out);
        return 0;
    }
    while (desc->Name) {
        const char *dll = (const char *)ImgPtr(desc->Name);
        IMAGE_THUNK_DATA *thunk;
        BYTE *cntPos;
        DWORD cnt = 0;
        if (!dll) break;
        *(DWORD *)p = desc->FirstThunk;
        p += 4;
        cntPos = p;
        *p++ = 0;
        while (*dll) { *p++ = (BYTE)*dll++; cnt++; }
        *cntPos = (BYTE)cnt;
        *p++ = 0;
        cntPos = p;
        *(DWORD *)p = 0;
        p += 4;
        thunk = (IMAGE_THUNK_DATA *)ImgPtr(desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk);
        while (thunk && thunk->u1.AddressOfData) {
            ULONGLONG v = thunk->u1.AddressOfData;
            if (v & IMAGE_ORDINAL_FLAG) {
                *p++ = 0;
                *(DWORD *)p = (DWORD)(v & 0x7FFFFFFF);
                p += 4;
            } else {
                const char *fn = (const char *)ImgPtr((DWORD)v);
                DWORD nl;
                if (!fn) { thunk++; continue; }
                nl = StrLenA(fn + 2);
                *p++ = (BYTE)nl;
                memcpy(p, fn + 2, nl);
                p += nl;
                *p++ = 0;
            }
            (*(DWORD *)cntPos)++;
            thunk++;
        }
        desc++;
    }
    *(DWORD *)p = 0;
    p += 4;
    g_impBuf = out;
    g_impSize = (DWORD)(p - out);
    return g_impSize;
}

static void ClearImport(void)
{
    DWORD dirRva = g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)ImgPtr(dirRva);
    while (desc && desc->Name) {
        char *dll = (char *)ImgPtr(desc->Name);
        IMAGE_THUNK_DATA *thunk;
        if (dll) memset(dll, 0, StrLenA(dll));
        thunk = (IMAGE_THUNK_DATA *)ImgPtr(desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk);
        while (thunk && thunk->u1.AddressOfData) {
            ULONGLONG v = thunk->u1.AddressOfData;
            if (!(v & IMAGE_ORDINAL_FLAG)) {
                WORD *h = (WORD *)ImgPtr((DWORD)v);
                if (h) memset(h, 0, StrLenA((char *)(h + 1)) + 2);
            }
            thunk->u1.AddressOfData = 0;
            thunk++;
        }
        memset(desc, 0, sizeof(*desc));
        desc++;
    }
    g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
    g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
}


/* ------------------------------------------------------------------ */
/* locate RT_MANIFEST in a mapped resource section; returns offset and
   size within the section, or 0 when absent */
static int ResFindManifest(BYTE *sec, DWORD secSize, DWORD *outOff, DWORD *outSize)
{
    DWORD base = 0;                    /* tree root at section start */
    DWORD off, dataRva, size;
    WORD i, named, ids;
    IMAGE_RESOURCE_DIRECTORY *dir;
    IMAGE_RESOURCE_DIRECTORY_ENTRY *e;
    /* level 1: type 24 */
    dir = (IMAGE_RESOURCE_DIRECTORY *)(sec + base);
    named = dir->NumberOfNamedEntries;
    ids = dir->NumberOfIdEntries;
    e = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(sec + base + sizeof(*dir));
    for (i = 0; i < named + ids; i++, e++) {
        if ((e->Name & 0x80000000) || e->Id != 24)
            continue;
        /* level 2: first name entry */
        off = e->OffsetToData & 0x7FFFFFFF;
        dir = (IMAGE_RESOURCE_DIRECTORY *)(sec + off);
        e = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(sec + off + sizeof(*dir));
        if (dir->NumberOfNamedEntries + dir->NumberOfIdEntries == 0)
            return 0;
        /* level 3: first lang entry */
        off = e->OffsetToData & 0x7FFFFFFF;
        dir = (IMAGE_RESOURCE_DIRECTORY *)(sec + off);
        e = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(sec + off + sizeof(*dir));
        if (dir->NumberOfNamedEntries + dir->NumberOfIdEntries == 0)
            return 0;
        dataRva = e->OffsetToData;     /* leaf: points at IMAGE_RESOURCE_DATA_ENTRY */
        {
            IMAGE_RESOURCE_DATA_ENTRY *de;
            DWORD leaf = dataRva;      /* already a direct data-entry offset */
            if (leaf + sizeof(*de) > secSize)
                return 0;
            de = (IMAGE_RESOURCE_DATA_ENTRY *)(sec + leaf);
            if (de->OffsetToData < (DWORD)(sec - g_image))
                return 0;
            *outOff = de->OffsetToData - (DWORD)(sec - g_image);
            *outSize = de->Size;
            if (*outOff + *outSize > secSize)
                return 0;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
static int __cdecl PackProgress(unsigned int total, unsigned int done)
{
    if (g_hProgress && total)
        SendMessageA(g_hProgress, PBM_SETPOS_, 100 - 100 * (total - done) / total, 0);
    return 1;
}

/* ------------------------------------------------------------------ */
/* section is compressible: name list, no import/export directory in   */
static int SectionPackable(PIMAGE_SECTION_HEADER s)
{
    static const char *names[] = { ".text", ".data", ".rdata", "CODE", "DATA", ".reloc" };
    DWORD impRva = g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD expRva = g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD span = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
    int k;
    if (impRva && impRva >= s->VirtualAddress && impRva - s->VirtualAddress < span)
        return 0;
    if (!g_MergeSections && expRva && expRva >= s->VirtualAddress &&
        expRva - s->VirtualAddress < span)
        return 0;
    for (k = 0; k < 6; k++)
        if (!strncmp((char *)s->Name, names[k], strlen(names[k])))
            return 1;
    return 0;
}

static void RandName(BYTE out[8])
{
    int len = 3 + (rand() % 5);
    int i;
    out[0] = '.';
    for (i = 1; i <= len; i++) out[i] = (BYTE)('a' + (rand() % 26));
    for (; i < 8; i++) out[i] = 0;
}

/* ------------------------------------------------------------------ */
static int ProtectFile(HWND hDlg)
{
    HANDLE hIn, hOut = INVALID_HANDLE_VALUE;
    DWORD fileSize, bytesRead, bytesWritten;
    DWORD i;
    BYTE *extra = NULL;
    DWORD extraSize = 0;
    BYTE *stage2 = NULL;
    DWORD stage2Size;
    BYTE *apBuf = NULL;
    DWORD apSize = 0;
    BYTE *work = NULL;
    BYTE *section = NULL;
    DWORD sectionSize, stubRva, stubVs, stubRawOff;
    PIMAGE_SECTION_HEADER stubSec;
    DWORD headSize, cur, oep, imageBase;
    DWORD resDirRva = 0;
    int hasManifest = 0;
    DWORD tlsRva, tlsSize;
    int rc = 0;

    g_Busy = 1;
    g_recCount = 0;
    if (g_hProgress) SendMessageA(g_hProgress, PBM_SETPOS_, 0, 0);

    if (g_CreateBak) {
        char bak[MAX_PATH];
        lstrcpyA(bak, g_fileName);
        strcat(bak, ".bak");
        CopyFileA(g_fileName, bak, FALSE);
    }
    hIn = CreateFileA(g_fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_EXISTING, 0, NULL);
    if (hIn == INVALID_HANDLE_VALUE) {
        AddLine(hDlg, "Error! Failed to open file!");
        g_Busy = 0;
        return 0;
    }
    {
        BYTE hdr[0x400];
        SetFilePointer(hIn, 0, NULL, FILE_BEGIN);
        ReadFile(hIn, hdr, sizeof(hdr), &bytesRead, NULL);
        g_peOffset = *(DWORD *)(hdr + 0x3C);
        g_fileAlign = *(DWORD *)(hdr + g_peOffset + 24 + 36);
        g_secAlign = *(DWORD *)(hdr + g_peOffset + 24 + 32);
        if (g_Align200) g_fileAlign = 512;
        g_imageSize = AlignUp(*(DWORD *)(hdr + g_peOffset + 24 + 56), g_secAlign);
        oep = *(DWORD *)(hdr + g_peOffset + 24 + 16);
        imageBase = *(DWORD *)(hdr + g_peOffset + 24 + 28);
        tlsRva = *(DWORD *)(hdr + g_peOffset + 24 + 96 + 9 * 8);
        tlsSize = *(DWORD *)(hdr + g_peOffset + 24 + 96 + 9 * 8 + 4);
    }
    fileSize = GetFileSize(hIn, NULL);
    g_image = (BYTE *)calloc(g_imageSize + 0x1000, 1);
    if (!g_image) { AddLine(hDlg, "Error! Not enough memory!"); goto done; }
    SetFilePointer(hIn, 0, NULL, FILE_BEGIN);
    ReadFile(hIn, g_image, fileSize, &bytesRead, NULL);
    g_nt = (PIMAGE_NT_HEADERS)(g_image + g_peOffset);
    g_nt->OptionalHeader.FileAlignment = g_fileAlign;
    g_nt->OptionalHeader.SizeOfImage = g_imageSize;
    g_numSec = g_nt->FileHeader.NumberOfSections;
    g_sec = (PIMAGE_SECTION_HEADER)((BYTE *)g_nt + 24 + g_nt->FileHeader.SizeOfOptionalHeader);
    /* normalize section sizes and load raw data at RVAs */
    for (i = 0; i < g_numSec; i++) {
        PIMAGE_SECTION_HEADER s = g_sec + i;
        if (s->SizeOfRawData) {
            SetFilePointer(hIn, s->PointerToRawData, NULL, FILE_BEGIN);
            ReadFile(hIn, g_image + s->VirtualAddress,
                     s->SizeOfRawData < g_imageSize - s->VirtualAddress ? s->SizeOfRawData
                                                                       : g_imageSize - s->VirtualAddress,
                     &bytesRead, NULL);
        }
        if (g_DelShare) s->Characteristics &= ~IMAGE_SCN_MEM_SHARED;
        s->Misc.VirtualSize = AlignUp(s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData,
                                      g_secAlign);
        if (s->VirtualAddress + s->Misc.VirtualSize > g_imageSize)
            s->Misc.VirtualSize = g_imageSize - s->VirtualAddress;
        s->SizeOfRawData = AlignUp(s->SizeOfRawData, g_fileAlign);
    }
    g_nt->OptionalHeader.SizeOfImage = g_imageSize;
    /* overlay data: only touched when the Keep-appended-data flag is live */
    if (g_SaveSData) {
        PIMAGE_SECTION_HEADER last = g_sec + g_numSec - 1;
        LONG end = (LONG)(last->PointerToRawData + last->SizeOfRawData);
        if ((LONG)fileSize > end) {
            extraSize = fileSize - (DWORD)end;
            extra = (BYTE *)calloc(extraSize, 1);
            SetFilePointer(hIn, end, NULL, FILE_BEGIN);
            ReadFile(hIn, extra, extraSize, &bytesRead, NULL);
            AddLine(hDlg, "Extra data read successfully.");
        } else {
            AddLine(hDlg, "No extra data found.");
        }
    }
    CloseHandle(hIn);
    AddLine(hDlg, "File read completed.");

    if (g_nt->OptionalHeader.Magic != 0x10B) {
        /* PE32+ (64-bit): the original's import walk fails the same way */
        AddLine(hDlg, "Insufficient memory or no import table in file.");
        goto done;
    }

    if (!(g_nt->FileHeader.Characteristics & IMAGE_FILE_DLL) && g_NoReloc) {
        DWORD dirRva = g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD dirSize = g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        BYTE *dir = (BYTE *)ImgPtr(dirRva);
        if (!dirRva || !dirSize || !dir) {
            AddLine(hDlg, "No relocation data found.");
        } else {
            for (i = 0; i < g_numSec; i++) {
                PIMAGE_SECTION_HEADER s = g_sec + i;
                if (!strncmp((char *)s->Name, ".reloc", 6) && dirRva == s->VirtualAddress) {
                    memset(dir, 0, dirSize < s->Misc.VirtualSize ? dirSize : s->Misc.VirtualSize);
                    s->SizeOfRawData = 0;
                    g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
                    g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
                    AddLine(hDlg, "Relocation data cleared.");
                    break;
                }
            }
            if (i == g_numSec) AddLine(hDlg, "No relocation section found.");
        }
    }

    /* strip debug sections (vx.xy): blank their raw data instead of
       removing the entries - the ARM64 x86 loader rejects images with
       virtual gaps between sections, so the VA layout must stay intact */
    if (g_StripDebug) {
        for (i = 0; i < g_numSec; i++) {
            PIMAGE_SECTION_HEADER s = g_sec + i;
            if (s->Name[0] == '/' || !strncmp((char *)s->Name, ".debug", 6)) {
                s->SizeOfRawData = 0;
                s->PointerToRawData = 0;
                memset(s->Name, 0, sizeof(s->Name));
                g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
                g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
            }
        }
    }

    /* import table obfuscation is always on (matches the original) */
    if (!BuildImpTable(hDlg)) goto done;
    ClearImport();
    AddLine(hDlg, "Import table encrypted successfully.");

    if (g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)
        AddLine(hDlg, g_PackRes ? "Resource section will be compressed."
                                : "Resources preserved in original section.");

    AddLine(hDlg, "Starting data compression...");
    hOut = CreateFileA(g_fileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                       NULL, CREATE_ALWAYS, 0, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        AddLine(hDlg, "Error! Failed to open file!");
        goto done;
    }
    headSize = AlignUp(g_nt->OptionalHeader.SizeOfHeaders, g_fileAlign);
    g_nt->OptionalHeader.SizeOfHeaders = headSize;
    if (!WriteFile(hOut, g_image, headSize, &bytesWritten, NULL) || bytesWritten != headSize) {
        AddLine(hDlg, "Error! File write failed!");
        goto done;
    }
    cur = headSize;
    work = (BYTE *)malloc(aP_workmem_size(0x10000));
    for (i = 0; i < g_numSec; i++) {
        PIMAGE_SECTION_HEADER s = g_sec + i;
        BYTE *data = (BYTE *)ImgPtr(s->VirtualAddress);
        DWORD len = s->SizeOfRawData;
        if (!len || !data) { s->SizeOfRawData = 0; continue; }
        /* trim trailing zeros over the live content */
        {
            DWORD live = s->Misc.VirtualSize < len ? s->Misc.VirtualSize : len;
            while (live && data[live - 1] == 0) live--;
            if (live == 0) {
                /* all-zero: drop the raw data, keep the original offset */
                s->SizeOfRawData = 0;
                continue;
            }
            len = live;
        }
        {
            DWORD resRva = g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            DWORD span = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
            int isRes = resRva && resRva >= s->VirtualAddress &&
                        resRva - s->VirtualAddress < span;
            int wantPack = SectionPackable(s) || (g_PackRes && isRes);
            if (g_PackRes && isRes) {
                /* vx.xy: compress the resource section but keep a valid
                   manifest visible for the loader (it reads .rsrc before
                   any code runs): [aP stream][minimal tree + manifest] */
                DWORD vs = s->Misc.VirtualSize;
                BYTE *src = data;
                BYTE *apd = (BYTE *)VirtualAlloc(NULL, vs + 0x1000, MEM_COMMIT, PAGE_READWRITE);
                BYTE *wm = (BYTE *)VirtualAlloc(NULL, aP_workmem_size(vs), MEM_COMMIT, PAGE_READWRITE);
                DWORD apn = 0;
                if (apd && wm)
                    apn = aP_pack(src, apd, vs, wm, PackProgress, NULL);
                if (wm) VirtualFree(wm, 0, MEM_RELEASE);
                if (apn) {
                    DWORD mOff = 0, mSize = 0;
                    DWORD treeBase = (apn + 3) & ~3u;
                    DWORD treeSize;
                    DWORD rawSize;
                    BYTE *out;
                    hasManifest = ResFindManifest(src, vs, &mOff, &mSize);
                    /* tree: root(16+8) type(16+8) name(16+8) lang(16+8) leaf(16) */
                    treeSize = hasManifest ? (16+8)*4 + 16 + mSize : 16;
                    rawSize = treeBase + treeSize;
                    out = (BYTE *)calloc(AlignUp(rawSize, g_fileAlign), 1);
                    if (out) {
                        DWORD r = s->VirtualAddress;
                        if (hasManifest) {
                            struct { DWORD chars, stamp, majv, minv, named, ids; } *d;
                            IMAGE_RESOURCE_DIRECTORY_ENTRY *e;
                            DWORD leafRva, blobRva;
                            d = (void *)(out + treeBase);
                            d->named = 0; d->ids = 1;
                            e = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(out + treeBase + 16);
                            e->Id = 24; e->OffsetToData = 0x80000000 | (32);
                            d = (void *)(out + treeBase + 32);
                            d->named = 0; d->ids = 1;
                            e = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(out + treeBase + 32 + 16);
                            e->Id = 1; e->OffsetToData = 0x80000000 | (64);
                            d = (void *)(out + treeBase + 64);
                            d->named = 0; d->ids = 1;
                            e = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(out + treeBase + 64 + 16);
                            e->Id = 0x409; e->OffsetToData = (96);
                            leafRva = r + treeBase + 96;
                            blobRva = r + treeBase + 96 + 16;
                            *(DWORD *)(out + treeBase + 96)     = blobRva;
                            *(DWORD *)(out + treeBase + 96 + 4) = mSize;
                            *(DWORD *)(out + treeBase + 96 + 8) = 0;
                            *(DWORD *)(out + treeBase + 96 + 12) = 0;
                            memcpy(out + treeBase + 96 + 16, src + mOff, mSize);
                        } else {
                            struct { DWORD chars, stamp, majv, minv, named, ids; } *d;
                            d = (void *)(out + treeBase);
                            d->named = 0; d->ids = 0;
                        }
                        memcpy(out, apd, apn);
                        if (!WriteFile(hOut, out, AlignUp(rawSize, g_fileAlign), &bytesWritten, NULL)) {
                            free(out);
                            VirtualFree(apd, 0, MEM_RELEASE);
                            AddLine(hDlg, "Error! File write failed!");
                            goto done;
                        }
                        free(out);
                        g_recs[g_recCount].vsize = vs;
                        g_recs[g_recCount].rva = s->VirtualAddress;
                        g_recs[g_recCount].packSize = apn;
                        g_recCount++;
                        AddLine(hDlg, "Resource section compressed.");
                        s->SizeOfRawData = AlignUp(rawSize, g_fileAlign);
                        s->PointerToRawData = cur;
                        s->Characteristics |= 0xC0000000u;
                        cur += s->SizeOfRawData;
                        resDirRva = r + treeBase;
                        VirtualFree(apd, 0, MEM_RELEASE);
                        continue;
                    }
                    free(out);
                }
                if (apd) VirtualFree(apd, 0, MEM_RELEASE);
                AddLine(hDlg, "Failed to compress data.");
                goto done;
            }
            if (!wantPack) {
                /* stored raw */
                DWORD sz = s->SizeOfRawData;
                if (!WriteFile(hOut, data, sz, &bytesWritten, NULL) || bytesWritten != sz) {
                    AddLine(hDlg, "Error! File write failed!");
                    goto done;
                }
                s->PointerToRawData = cur;
                cur += sz;
                continue;
            }
        }
        {
            BYTE *copy = (BYTE *)VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_READWRITE);
            BYTE *dst = (BYTE *)VirtualAlloc(NULL, len + 16, MEM_COMMIT, PAGE_READWRITE);
            BYTE *wm = (BYTE *)VirtualAlloc(NULL, aP_workmem_size(len), MEM_COMMIT, PAGE_READWRITE);
            DWORD packed = 0;
            if (copy && dst && wm) {
                memcpy(copy, data, len);
                packed = aP_pack(copy, dst, len, wm, PackProgress, NULL);
            }
            if (!packed) {
                if (dst) VirtualFree(dst, 0, MEM_RELEASE);
                if (copy) VirtualFree(copy, 0, MEM_RELEASE);
                if (wm) VirtualFree(wm, 0, MEM_RELEASE);
                AddLine(hDlg, "Failed to compress data.");
                goto done;
            }
            if (!WriteFile(hOut, dst, packed, &bytesWritten, NULL) || bytesWritten != packed) {
                VirtualFree(dst, 0, MEM_RELEASE);
                AddLine(hDlg, "Error! File write failed!");
                goto done;
            }
            {
                DWORD aligned = AlignUp(packed, g_fileAlign);
                BYTE z = 0;
                while (aligned > packed)
                    WriteFile(hOut, &z, 1, &bytesWritten, NULL), aligned--;
            }
            VirtualFree(dst, 0, MEM_RELEASE);
            VirtualFree(copy, 0, MEM_RELEASE);
            VirtualFree(wm, 0, MEM_RELEASE);
            g_recs[g_recCount].vsize = s->Misc.VirtualSize;
            g_recs[g_recCount].rva = s->VirtualAddress;
            g_recs[g_recCount].packSize = AlignUp(packed, g_fileAlign);
            g_recCount++;
            AddLine(hDlg, "Section compressed successfully.");
            s->SizeOfRawData = AlignUp(packed, g_fileAlign);
            s->PointerToRawData = cur;
            s->Characteristics |= 0xC0000000u;
            cur += s->SizeOfRawData;
        }
    }
    free(work);
    work = NULL;

    /* ---- second stage: template + patches + records + import blob ---- */
    stage2Size = STUB2_SIZE + g_impSize;
    stage2 = (BYTE *)calloc(stage2Size + 16, 1);
    if (!stage2) { AddLine(hDlg, "Error! Out of memory!"); goto done; }
    memcpy(stage2, stub_stage2, STUB2_SIZE);
    *(DWORD *)(stage2 + S2_OEP) = oep;
    *(DWORD *)(stage2 + S2_ISPROTIMP) = 1;
    *(DWORD *)(stage2 + S2_IMPOFFSET) = STUB2_SIZE;
    *(DWORD *)(stage2 + S2_ISDLL) = (g_nt->FileHeader.Characteristics & IMAGE_FILE_DLL) ? 1 : 0;
    *(DWORD *)(stage2 + S2_TLSDIRRVA) = (tlsRva && (g_nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) ? tlsRva : 0;
    *(DWORD *)(stage2 + S2_IMAGEBASE) = imageBase;
    *(DWORD *)(stage2 + S2_HASTLS) = tlsRva ? 1 : 0;
    *(DWORD *)(stage2 + S2_FEATURES) = (g_AnalyzeImmunity ? 1 : 0) |
                                       (g_BlacklistScan ? 2 : 0) |
                                       (g_MemoryShield ? 4 : 0) |
                                       (g_HeaderShield ? 8 : 0);
    memset(stage2 + S2_RECORDS, 0, sizeof(g_recs));
    memcpy(stage2 + S2_RECORDS, g_recs, g_recCount * sizeof(PACKREC));
    memcpy(stage2 + STUB2_SIZE, g_impBuf, g_impSize);

    /* aP-pack + XOR */
    apBuf = (BYTE *)malloc(stage2Size + 0x10000);
    work = (BYTE *)VirtualAlloc(NULL, aP_workmem_size(stage2Size), MEM_COMMIT, PAGE_READWRITE);
    if (!apBuf || !work) { AddLine(hDlg, "Error! Out of memory!"); goto done; }
    apSize = aP_pack(stage2, apBuf, stage2Size, work, PackProgress, NULL);
    VirtualFree(work, 0, MEM_RELEASE);
    work = NULL;
    if (!apSize) { AddLine(hDlg, "Failed to build shell!"); goto done; }
    {
        BYTE key = (BYTE)(rand() % 255 + 1);
        DWORD k;
        for (k = 0; k < apSize; k++) apBuf[k] ^= key;
        sectionSize = STUB1_SIZE + apSize;
        section = (BYTE *)calloc(AlignUp(sectionSize, g_fileAlign), 1);
        if (!section) { AddLine(hDlg, "Error! Out of memory!"); goto done; }
        memcpy(section, stub_stage1, STUB1_SIZE);
        memcpy(section + STUB1_SIZE, apBuf, apSize);
        *(DWORD *)(section + S1_SHELLBASE) = STUB1_SIZE;
        *(DWORD *)(section + S1_PACKSIZE) = stage2Size;
        *(DWORD *)(section + S1_BLOBLEN) = apSize;
        section[S1_XORKEY] = key;
        stubRva = AlignUp(g_imageSize, g_secAlign);
        /* import block RVA fixups */
        *(DWORD *)(section + 0x06) += stubRva + 6;
        *(DWORD *)(section + 0x12) += stubRva + 6;
        *(DWORD *)(section + 0x16) += stubRva + 6;
        *(DWORD *)(section + 0x2E) += stubRva + 6;
        *(DWORD *)(section + 0x32) += stubRva + 6;
        *(DWORD *)(section + 0x36) += stubRva + 6;
        *(DWORD *)(section + 0x3E) += stubRva + 6;
        *(DWORD *)(section + 0x42) += stubRva + 6;
        *(DWORD *)(section + 0x46) += stubRva + 6;
        /* TLS passthrough via the stub trampoline */
        if (tlsRva && ImgPtr(tlsRva)) {
            memcpy(section + S1_TLSDIR, ImgPtr(tlsRva), 0x18);
            *(DWORD *)(section + S1_TLSDIR + 0x0C) = imageBase + stubRva + S1_TLSCBARRAY;
            memcpy(section + S1_TLSSAVED, ImgPtr(tlsRva), 0x18);
            *(DWORD *)(section + S1_TLSCBARRAY) = imageBase + stubRva + 0xE4;
            *(DWORD *)(section + S1_TLSCBARRAY + 4) = 0;
            g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress =
                stubRva + S1_TLSDIR;
            g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0x18;
        } else {
            g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
            g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
        }
    }

    /* ---- section table: rename, add .stub ---- */
    {
        DWORD resRva = g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        for (i = 0; i < g_numSec; i++) {
            PIMAGE_SECTION_HEADER s = g_sec + i;
            DWORD span = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
            int isRes = resRva && resRva >= s->VirtualAddress && resRva - s->VirtualAddress < span;
            if (isRes && !g_PackRes)
                continue; /* raw resource section keeps its name */
            RandName(s->Name);
        }
    }
    stubVs = AlignUp(sectionSize, g_secAlign);
    stubSec = g_sec + g_numSec;
    memset(stubSec, 0, sizeof(*stubSec));
    memcpy(stubSec->Name, ".stub", 5);
    stubSec->Misc.VirtualSize = stubVs;
    stubSec->VirtualAddress = stubRva;
    stubSec->SizeOfRawData = AlignUp(sectionSize, g_fileAlign);
    stubSec->Characteristics = 0xE0000040u;
    stubRawOff = cur;
    stubSec->PointerToRawData = stubRawOff;
    g_nt->FileHeader.NumberOfSections++;

    /* ---- header updates ---- */
    g_nt->OptionalHeader.AddressOfEntryPoint = stubRva;
    g_nt->OptionalHeader.SizeOfImage = stubRva + stubVs;
    g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = stubRva + 6;
    g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0x8C;
    g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
    g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
    if (resDirRva) {
        g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = resDirRva;
        g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 0x18;
    }
    for (i = 0; i < 16; i++) {
        if (i == IMAGE_DIRECTORY_ENTRY_IMPORT || i == IMAGE_DIRECTORY_ENTRY_RESOURCE ||
            i == IMAGE_DIRECTORY_ENTRY_TLS)
            continue;
        g_nt->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
        g_nt->OptionalHeader.DataDirectory[i].Size = 0;
    }
    g_nt->OptionalHeader.DllCharacteristics = 0x8000;
    g_nt->OptionalHeader.CheckSum = 0;
    if (g_ClsSecName) {
        for (i = 0; i < g_numSec; i++)
            memset(g_sec[i].Name, 0, sizeof(g_sec[i].Name));
    }

    /* ---- clamp raw offsets the output no longer covers (dropped
       all-zero sections can keep offsets beyond a shrunk file) ---- */
    {
        DWORD finalSize = stubRawOff + stubSec->SizeOfRawData + extraSize;
        for (i = 0; i <= g_numSec; i++) {
            PIMAGE_SECTION_HEADER s = g_sec + i;
            if (s->SizeOfRawData == 0 &&
                s->PointerToRawData && s->PointerToRawData >= finalSize)
                s->PointerToRawData = 0;
        }
    }

    /* ---- final writes ---- */
    SetFilePointer(hOut, 0, NULL, FILE_BEGIN);
    if (!WriteFile(hOut, g_image, headSize, &bytesWritten, NULL)) {
        AddLine(hDlg, "Error! File write failed!");
        goto done;
    }
    SetFilePointer(hOut, stubRawOff, NULL, FILE_BEGIN);
    if (!WriteFile(hOut, section, stubSec->SizeOfRawData, &bytesWritten, NULL)) {
        AddLine(hDlg, "Error! File write failed!");
        goto done;
    }
    if (extraSize) {
        SetFilePointer(hOut, 0, NULL, FILE_END);
        WriteFile(hOut, extra, extraSize, &bytesWritten, NULL);
        AddLine(hDlg, "Extra data written successfully.");
    }
    EnableWindow(GetDlgItem(hDlg, IDC_OPEN), TRUE);
    {
        DWORD newSize = SetFilePointer(hOut, 0, NULL, FILE_END);
        char buf[256];
        wsprintfA(buf, "Original file size: %u kilobytes", fileSize >> 10);
        AddLine(hDlg, buf);
        wsprintfA(buf, "Packed file size: %u kilobytes", newSize >> 10);
        AddLine(hDlg, buf);
        if (fileSize) {
            DWORD64 diff = fileSize > newSize ? fileSize - newSize : 0;
            DWORD64 ratio = 1000 * diff / fileSize;
            wsprintfA(buf, "Compression ratio: %u.%u%%", (DWORD)(ratio / 10), (DWORD)(ratio % 10));
            AddLine(hDlg, buf);
        }
    }
    if (g_hProgress) SendMessageA(g_hProgress, PBM_SETPOS_, 100, 0);
    AddLine(hDlg, "Encryption completed!");
    rc = 1;
done:
    if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
    free(g_image); g_image = NULL;
    free(extra);
    free(stage2);
    free(apBuf);
    free(section);
    free(work);
    if (g_impBuf) { free(g_impBuf); g_impBuf = NULL; }
    g_Busy = 0;
    return rc;
}

static unsigned int __stdcall ProtectThread(void *param)
{
    ProtectFile((HWND)param);
    g_Busy = 0;
    return 0;
}

/* ------------------------------------------------------------------ */
static INT_PTR CALLBACK AboutProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_INITDIALOG: {
        HWND hIcon = GetDlgItem(hDlg, IDC_ABOUTICON);
        RECT rc;
        int cx, cy;
        HICON ico;
        GetClientRect(hIcon, &rc);
        cx = rc.right - rc.left;
        cy = rc.bottom - rc.top;
        if (cx < 1) cx = GetSystemMetrics(SM_CXICON);
        if (cy < 1) cy = GetSystemMetrics(SM_CYICON);
        ico = (HICON)LoadImageA(g_hInst, MAKEINTRESOURCEA(IDI_APP), IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR);
        if (ico)
            SendMessageA(hIcon, STM_SETICON, (WPARAM)ico, 0);
        SetDlgItemTextW(hDlg, IDC_ABOUTBOOK, L"\x300a\x52a0\x5bc6\x4e0e\x89e3\x5bc6\x300b(\x7b2c\x4e09\x7248)");
        return 1;
    }
    case WM_DESTROY: {
        HICON ico = (HICON)SendDlgItemMessageA(hDlg, IDC_ABOUTICON, STM_GETICON, 0, 0);
        if (ico) DestroyIcon(ico);
        return 1;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == 1 || LOWORD(wp) == 2) { EndDialog(hDlg, 0); return 1; }
        break;
    case WM_LBUTTONDOWN:
        PostMessageA(hDlg, WM_NCLBUTTONDOWN, HTCAPTION, 0);
        return 1;
    }
    (void)lp;
    return 0;
}

static BOOL PickFile(HWND hDlg)
{
    OPENFILENAMEA ofn;
    memset(g_fileName, 0, MAX_PATH);
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hDlg;
    ofn.hInstance = g_hInst;
    ofn.lpstrFile = g_fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = "Open ...";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_EXPLORER;
    ofn.lpstrFilter = "PE Files (*.exe;*.dll)\0*.EXE;*.DLL\0All Files (*.*)\0*.*\0";
    if (!GetOpenFileNameA(&ofn)) return FALSE;
    SendDlgItemMessageA(hDlg, IDC_LOG, WM_SETTEXT, 0, 0);
    return TRUE;
}

static void OnFileChosen(HWND hDlg)
{
    BOOL ok;
    AddLine(hDlg, g_fileName);
    ok = CheckTarget(hDlg);
    EnableWindow(GetDlgItem(hDlg, IDC_PROTECT), ok);
    if (g_hProgress) SendMessageA(g_hProgress, PBM_SETPOS_, 0, 0);
}

static INT_PTR CALLBACK MainChildProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_INITDIALOG:
        DragAcceptFiles(hDlg, TRUE);
        g_hProgress = GetDlgItem(hDlg, PROGRESS_CTRL);
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_PROTECT: {
            HANDLE h;
            EnableWindow(GetDlgItem(hDlg, IDC_PROTECT), FALSE);
            EnableWindow(GetDlgItem(hDlg, IDC_OPEN), FALSE);
            h = (HANDLE)_beginthreadex(NULL, 0, ProtectThread, hDlg, 0, NULL);
            if (h) CloseHandle(h);
            return 1;
        }
        case IDC_EXIT:
            SendMessageA(GetParent(GetParent(hDlg)), WM_CLOSE, 0, 0);
            return 1;
        case IDC_OPEN:
            EnableWindow(GetDlgItem(hDlg, IDC_PROTECT), FALSE);
            if (PickFile(hDlg)) {
                SetDlgItemTextA(hDlg, IDC_FILE, g_fileName);
                OnFileChosen(hDlg);
            }
            EnableWindow(GetDlgItem(hDlg, IDC_OPEN), TRUE);
            return 1;
        case IDC_TOPMOST: {
            HWND top = GetParent(GetParent(hDlg));
            SetWindowPos(top, (SendDlgItemMessageA(hDlg, IDC_TOPMOST, BM_GETCHECK, 0, 0) == BST_CHECKED)
                ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            return 1;
        }
        }
        break;
    case WM_DROPFILES: {
        HDROP drop = (HDROP)wp;
        if (!g_Busy) {
            SendDlgItemMessageA(hDlg, IDC_LOG, WM_SETTEXT, 0, 0);
            memset(g_fileName, 0, MAX_PATH);
            DragQueryFileA(drop, 0, g_fileName, MAX_PATH);
            DragFinish(drop);
            SetDlgItemTextA(hDlg, IDC_FILE, g_fileName);
            OnFileChosen(hDlg);
        }
        return 0;
    }
    }
    (void)lp;
    return 0;
}

static INT_PTR CALLBACK OptChildProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_INITDIALOG)
        LoadOptionsUI(hDlg);
    (void)wp; (void)lp;
    return 0;
}

static INT_PTR CALLBACK MainProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_INITDIALOG:
        g_hMain = hDlg;
        g_logBuf = (char *)calloc(0x10000, 1);
        {
            HICON big = (HICON)LoadImageA(g_hInst, MAKEINTRESOURCEA(IDI_APP), IMAGE_ICON,
                GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_SHARED);
            HICON small = (HICON)LoadImageA(g_hInst, MAKEINTRESOURCEA(IDI_APP), IMAGE_ICON,
                GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED);
            SendMessageA(hDlg, WM_SETICON, ICON_BIG, (LPARAM)big);
            SendMessageA(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)small);
            if (big) SetClassLongA(hDlg, GCL_HICON, (LONG)(LONG_PTR)big);
            if (small) SetClassLongA(hDlg, GCL_HICONSM, (LONG)(LONG_PTR)small);
        }
        EnableWindow(GetDlgItem(hDlg, IDC_PROTECT), FALSE);
        InitCommonControls();
        g_hTab = GetDlgItem(hDlg, IDC_TAB);
        {
            TCITEMA tie;
            tie.mask = TCIF_TEXT;
            tie.pszText = (LPSTR)"Main";
            SendMessageA(g_hTab, TCM_INSERTITEMA, 0, (LPARAM)&tie);
            tie.pszText = (LPSTR)"Options";
            SendMessageA(g_hTab, TCM_INSERTITEMA, 1, (LPARAM)&tie);
        }
        g_hChildMain = CreateDialogParamA(g_hInst, MAKEINTRESOURCEA(IDD_MAINCHILD), g_hTab, MainChildProc, 0);
        g_hChildOpt = CreateDialogParamA(g_hInst, MAKEINTRESOURCEA(IDD_OPTIONS), g_hTab, OptChildProc, 0);
        ShowWindow(g_hChildMain, SW_SHOW);
        return 0;
    case WM_NOTIFY: {
        NMHDR *nm = (NMHDR *)lp;
        if (nm->idFrom == IDC_TAB && nm->code == TCN_SELCHANGE) {
            int sel = (int)SendMessageA(g_hTab, TCM_GETCURSEL, 0, 0);
            if (sel == 0) OptionsFromUI(g_hChildOpt);
            ShowWindow(g_hChildMain, sel == 0 ? SW_SHOW : SW_HIDE);
            ShowWindow(g_hChildOpt, sel == 1 ? SW_SHOW : SW_HIDE);
            if (sel == 0) SaveOptionsUI(g_hChildOpt);
        }
        return 0;
    }
    case WM_CLOSE:
        if (g_Busy) {
            MessageBoxA(NULL, "Compressing in progress, cannot exit!", "Warning", MB_OK);
            return 1;
        }
        free(g_logBuf);
        g_logBuf = NULL;
        EndDialog(hDlg, 0);
        return 1;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case 40002:
            DialogBoxParamA(g_hInst, MAKEINTRESOURCEA(IDD_ABOUT), hDlg, AboutProc, 0);
            return 1;
        case 40003:
            SendMessageA(g_hChildMain, WM_COMMAND, MAKEWPARAM(IDC_OPEN, 0), 0);
            return 1;
        case 40004:
            SendMessageA(hDlg, WM_CLOSE, 0, 0);
            return 1;
        }
        break;
    }
    return 0;
}

#ifdef PEARMOR_CLI

static const char *const kCliBanner[] = {
    "  _.--^--._                           ",
    "|`  20:26  `|                         ",
    "|  ___ ___  |   _                     ",
    "|.| _ \\ __|.|  /_\\  _ _ _ __  ___ _ _ ",
    "| |  _/ _|  | / _ \\| '_| '  \\/ _ \\ '_|",
    "| |_| |___| |/_/ \\_\\_| |_|_|_\\___/_|  ",
    "\\     :     /                   vxx.xy",
    " \\    :    /                          ",
    "  `-.SCT.-`                           ",
    "      `                               ",
};

static void CliBanner(void)
{
    int i;
    for (i = 0; i < (int)(sizeof(kCliBanner) / sizeof(kCliBanner[0])); i++)
        puts(kCliBanner[i]);
    putchar('\n');
}

static void CliUsage(void)
{
    printf("usage: pearmor-cli <file.exe> [options]\n\n");
    printf("options (default in brackets):\n");
    printf("  --strip-debug / --no-strip-debug   strip debug sections [on]\n");
    printf("  --pack-res / --no-pack-res         compress the resource section [off]\n");
    printf("  --bak / --no-bak                   create .bak backup [off]\n");
    printf("  --save-sdata / --no-save-sdata     keep appended overlay data [off]\n");
    printf("  --no-reloc / --keep-reloc          clear relocation data [off]\n");
    printf("  --align200 / --no-align200         force 0x200 file alignment [off]\n");
    printf("  --merge / --no-merge               merge compressible sections [off]\n");
    printf("  --clsname / --no-clsname           randomize section names [off]\n");
    printf("  --delshare / --no-delshare         drop shared section flag [off]\n");
    printf("  --anti-debug / --no-anti-debug     anti-debug in packed file [on]\n");
    printf("  --anti-dump / --no-anti-dump       anti-dump in packed file [on]\n");
    printf("  --detect / --no-detect             debugger detection [off]\n");
    printf("  --header / --no-header             header protection [off]\n");
}

int main(int argc, char **argv)
{
    int i;
    g_hInst = GetModuleHandleA(NULL);
    ReadIni();
    CliBanner();
    if (argc < 2 || !argv[1][0] || argv[1][0] == '-') {
        CliUsage();
        return 1;
    }
    lstrcpynA(g_fileName, argv[1], MAX_PATH);
    for (i = 2; i < argc; i++) {
        if (!stricmp(argv[i], "--strip-debug")) g_StripDebug = 1;
        else if (!stricmp(argv[i], "--no-strip-debug")) g_StripDebug = 0;
        else if (!stricmp(argv[i], "--pack-res")) g_PackRes = 1;
        else if (!stricmp(argv[i], "--no-pack-res")) g_PackRes = 0;
        else if (!stricmp(argv[i], "--bak")) g_CreateBak = 1;
        else if (!stricmp(argv[i], "--no-bak")) g_CreateBak = 0;
        else if (!stricmp(argv[i], "--save-sdata")) g_SaveSData = 1;
        else if (!stricmp(argv[i], "--no-save-sdata")) g_SaveSData = 0;
        else if (!stricmp(argv[i], "--no-reloc")) g_NoReloc = 1;
        else if (!stricmp(argv[i], "--keep-reloc")) g_NoReloc = 0;
        else if (!stricmp(argv[i], "--align200")) g_Align200 = 1;
        else if (!stricmp(argv[i], "--no-align200")) g_Align200 = 0;
        else if (!stricmp(argv[i], "--merge")) g_MergeSections = 1;
        else if (!stricmp(argv[i], "--no-merge")) g_MergeSections = 0;
        else if (!stricmp(argv[i], "--clsname")) g_ClsSecName = 1;
        else if (!stricmp(argv[i], "--no-clsname")) g_ClsSecName = 0;
        else if (!stricmp(argv[i], "--delshare")) g_DelShare = 1;
        else if (!stricmp(argv[i], "--no-delshare")) g_DelShare = 0;
        else if (!stricmp(argv[i], "--anti-debug")) g_AnalyzeImmunity = 1;
        else if (!stricmp(argv[i], "--no-anti-debug")) g_AnalyzeImmunity = 0;
        else if (!stricmp(argv[i], "--anti-dump")) g_MemoryShield = 1;
        else if (!stricmp(argv[i], "--no-anti-dump")) g_MemoryShield = 0;
        else if (!stricmp(argv[i], "--detect")) g_BlacklistScan = 1;
        else if (!stricmp(argv[i], "--no-detect")) g_BlacklistScan = 0;
        else if (!stricmp(argv[i], "--header")) g_HeaderShield = 1;
        else if (!stricmp(argv[i], "--no-header")) g_HeaderShield = 0;
        else { printf("unknown option: %s\n", argv[i]); CliUsage(); return 1; }
    }
    g_logBuf = (char *)calloc(0x10000, 1);
    AddLine(NULL, g_fileName);
    {
        int ok = ProtectFile(NULL);
        free(g_logBuf);
        g_logBuf = NULL;
        return ok ? 0 : 1;
    }
}

#else /* GUI build */

int main(int argc, char **argv)
{
    MSG msg;
    g_hInst = GetModuleHandleA(NULL);
    ReadIni();
    if (argc > 1 && argv[1] && argv[1][0]) {
        lstrcpynA(g_fileName, argv[1], MAX_PATH);
        g_logBuf = (char *)calloc(0x10000, 1);
        ProtectFile(NULL);
        free(g_logBuf);
        return 0;
    }
    DialogBoxParamA(g_hInst, MAKEINTRESOURCEA(IDD_MAIN), NULL, MainProc, 0);
    (void)msg;
    return 0;
}

#endif /* PEARMOR_CLI */
