#pragma once
#include <Windows.h>
// 先引入 SDK 的 winternl.h，复用其中的 _SYSTEM_INFORMATION_CLASS /
// _CLIENT_ID / _UNICODE_STRING / _SYSTEM_THREAD_INFORMATION 等定义，
// 避免各 exp 的 def.hpp 已包含 winternl.h 时本文件重复定义导致 C2011。
#include <winternl.h>
#include <iostream>
#include <cstdio>
#include <vector>

#define MAXIMUM_FILENAME_LENGTH 255
#define SystemExtendedHandleInformation 64
#define SystemBigPoolInformation 66
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// winternl.h 的 SYSTEM_INFORMATION_CLASS 枚举中没有下面这两个值，单独补充
inline constexpr SYSTEM_INFORMATION_CLASS SystemModuleInformation =
	static_cast<SYSTEM_INFORMATION_CLASS>(11);
inline constexpr SYSTEM_INFORMATION_CLASS SystemExtendedProcessInformation =
	static_cast<SYSTEM_INFORMATION_CLASS>(57);

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef struct SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
#ifdef _WIN64
	ULONG				Reserved3;
#endif
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG ModulesCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

////////////////////////////
// KPRIORITY / CLIENT_ID / UNICODE_STRING 均已由 winternl.h 定义
// （其中 CLIENT_ID 的 UniqueProcess/UniqueThread 为 HANDLE，与内核结构
//   在 64 位下大小一致），直接复用即可。


//from http://boinc.berkeley.edu/android-boinc/boinc/lib/diagnostics_win.h
typedef struct _VM_COUNTERS {
	// the following was inferred by painful reverse engineering
	SIZE_T		   PeakVirtualSize;	// not actually
	SIZE_T         PageFaultCount;
	SIZE_T         PeakWorkingSetSize;
	SIZE_T         WorkingSetSize;
	SIZE_T         QuotaPeakPagedPoolUsage;
	SIZE_T         QuotaPagedPoolUsage;
	SIZE_T         QuotaPeakNonPagedPoolUsage;
	SIZE_T         QuotaNonPagedPoolUsage;
	SIZE_T         PagefileUsage;
	SIZE_T         PeakPagefileUsage;
	SIZE_T         VirtualSize;		// not actually
} VM_COUNTERS;

// KWAIT_REASON / SYSTEM_THREAD_INFORMATION 由 winternl.h 定义（其 CLIENT_ID
// 为 HANDLE 对，布局与内核真实结构一致），此处不再重复定义。

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebAddress; /* This is only filled in on Vista and above */
	ULONG Reserved1;
	ULONG Reserved2;
	ULONG Reserved3;
} SYSTEM_EXTENDED_THREAD_INFORMATION, * PSYSTEM_EXTENDED_THREAD_INFORMATION;
typedef struct _SYSTEM_EXTENDED_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID PageDirectoryBase;
	VM_COUNTERS VirtualMemoryCounters;
	SIZE_T PrivatePageCount;
	IO_COUNTERS IoCounters;
	SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1];
} SYSTEM_EXTENDED_PROCESS_INFORMATION, * PSYSTEM_EXTENDED_PROCESS_INFORMATION;

////////////////////////////
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX,
* PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX,
* PSYSTEM_HANDLE_INFORMATION_EX;


// 定义必要的结构体（如果未包含在 winternl.h 中）
typedef struct _SYSTEM_BIGPOOL_ENTRY {
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	SIZE_T SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
	// Padding 隐含在此处
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

///////////////////////////

typedef struct stackinfo {
	wchar_t* ModuleName;
	unsigned long long result;
}StackInfo, * pStackInfo;

namespace exploit
{
	namespace memtools
	{
		unsigned long long ulGetKernelBase(const PCHAR ModuleName);
		unsigned long long ulGetStackLimit(const LPCWSTR ProcessName);
		unsigned long long ulGetStackLimitWithInfo(pStackInfo stackinfo);
		unsigned long long ulUseStackInfo(wchar_t ProcName[]);
		bool bFindHandleObject(DWORD targetPid, ULONG_PTR targetHandle, ULONG_PTR result);
		unsigned long long ulFindKernelPoolAddress(ULONG targetTag, SIZE_T targetSize, PUINT64 outAddresses, ULONG maxCount);
		void hexdump(const void* data, ULONG size);
	} // namespace memtools

} // namespace exploit