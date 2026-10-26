#pragma once
#include <windows.h>
#include <iostream>
#include <winternl.h>
#include <WinBase.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <cstdio>
#include <ioringapi.h>
#include <winternl.h>
#include "include/common/memtools.hpp"


namespace CVE_2023_21768
{
    typedef struct _afdStruct
    {
        HANDLE validHandle;
        void* ptr;
        void* valPtr1;
        void* valPtr2; //unsigned int*也可以
        DWORD loopCount1;
        DWORD val3;
        DWORD val4;
    }afdStruct, * pAfdStruct;

    typedef NTSTATUS(NTAPI* NtSetIoCompletion_t)(
        HANDLE,
        PVOID,
        PVOID,
        NTSTATUS,
        ULONG_PTR
        );

    typedef struct _IO_RING_STRUCTV1
    {
        ULONG IoRingVersion;
        ULONG SubmissionQueueSize;
        ULONG CompletionQueueSize;
        ULONG RequiredFlags;
        ULONG AdvisoryFlags;
    } IO_RING_STRUCTV1, * PIO_RING_STRUCTV1;

    typedef struct _IORING_QUEUE_HEAD
    {
        ULONG Head;
        ULONG Tail;
        ULONG64 Flags;
    } IORING_QUEUE_HEAD, * PIORING_QUEUE_HEAD;

    typedef struct _NT_IORING_INFO
    {
        ULONG Version;
        IORING_CREATE_FLAGS Flags;
        ULONG SubmissionQueueSize;
        ULONG SubQueueSizeMask;
        ULONG CompletionQueueSize;
        ULONG CompQueueSizeMask;
        PIORING_QUEUE_HEAD SubQueueBase;
        PVOID CompQueueBase;
    } NT_IORING_INFO, * PNT_IORING_INFO;

    typedef struct _NT_IORING_SQE
    {
        ULONG Opcode;
        ULONG Flags;
        HANDLE FileRef;
        LARGE_INTEGER FileOffset;
        PVOID Buffer;
        ULONG BufferSize;
        ULONG BufferOffset;
        ULONG Key;
        PVOID Unknown;
        PVOID UserData;
        PVOID stuff1;
        PVOID stuff2;
        PVOID stuff3;
        PVOID stuff4;
    } NT_IORING_SQE, * PNT_IORING_SQE;

    EXTERN_C_START
        NTSTATUS
        NtSubmitIoRing(
            _In_ HANDLE Handle,
            _In_ IORING_CREATE_REQUIRED_FLAGS Flags,
            _In_ ULONG EntryCount,
            _In_ PLARGE_INTEGER Timeout
        );

    NTSTATUS
        NtCreateIoRing(
            _Out_ PHANDLE pIoRingHandle,
            _In_ ULONG CreateParametersSize,
            _In_ PIO_RING_STRUCTV1 CreateParameters,
            _In_ ULONG OutputParametersSize,
            _Out_ PNT_IORING_INFO pRingInfo
        );

    NTSTATUS
        NtClose(
            _In_ HANDLE Handle
        );

    EXTERN_C_END

        typedef struct _DISPATCHER_HEADER
    {
        union
        {
            /* 0x0000 */ volatile long Lock;
            /* 0x0000 */ long LockNV;
            struct
            {
                /* 0x0000 */ unsigned char Type;
                /* 0x0001 */ unsigned char Signalling;
                /* 0x0002 */ unsigned char Size;
                /* 0x0003 */ unsigned char Reserved1;
            }; /* size: 0x0004 */
            struct
            {
                /* 0x0000 */ unsigned char TimerType;
                union
                {
                    /* 0x0001 */ unsigned char TimerControlFlags;
                    struct
                    {
                        struct /* bitfield */
                        {
                            /* 0x0001 */ unsigned char Absolute : 1; /* bit position: 0 */
                            /* 0x0001 */ unsigned char Wake : 1; /* bit position: 1 */
                            /* 0x0001 */ unsigned char EncodedTolerableDelay : 6; /* bit position: 2 */
                        }; /* bitfield */
                        /* 0x0002 */ unsigned char Hand;
                        union
                        {
                            /* 0x0003 */ unsigned char TimerMiscFlags;
                            struct /* bitfield */
                            {
                                /* 0x0003 */ unsigned char Index : 6; /* bit position: 0 */
                                /* 0x0003 */ unsigned char Inserted : 1; /* bit position: 6 */
                                /* 0x0003 */ volatile unsigned char Expired : 1; /* bit position: 7 */
                            }; /* bitfield */
                        }; /* size: 0x0001 */
                    }; /* size: 0x0003 */
                }; /* size: 0x0003 */
            }; /* size: 0x0004 */
            struct
            {
                /* 0x0000 */ unsigned char Timer2Type;
                union
                {
                    /* 0x0001 */ unsigned char Timer2Flags;
                    struct
                    {
                        struct /* bitfield */
                        {
                            /* 0x0001 */ unsigned char Timer2Inserted : 1; /* bit position: 0 */
                            /* 0x0001 */ unsigned char Timer2Expiring : 1; /* bit position: 1 */
                            /* 0x0001 */ unsigned char Timer2CancelPending : 1; /* bit position: 2 */
                            /* 0x0001 */ unsigned char Timer2SetPending : 1; /* bit position: 3 */
                            /* 0x0001 */ unsigned char Timer2Running : 1; /* bit position: 4 */
                            /* 0x0001 */ unsigned char Timer2Disabled : 1; /* bit position: 5 */
                            /* 0x0001 */ unsigned char Timer2ReservedFlags : 2; /* bit position: 6 */
                        }; /* bitfield */
                        /* 0x0002 */ unsigned char Timer2ComponentId;
                        /* 0x0003 */ unsigned char Timer2RelativeId;
                    }; /* size: 0x0003 */
                }; /* size: 0x0003 */
            }; /* size: 0x0004 */
            struct
            {
                /* 0x0000 */ unsigned char QueueType;
                union
                {
                    /* 0x0001 */ unsigned char QueueControlFlags;
                    struct
                    {
                        struct /* bitfield */
                        {
                            /* 0x0001 */ unsigned char Abandoned : 1; /* bit position: 0 */
                            /* 0x0001 */ unsigned char DisableIncrement : 1; /* bit position: 1 */
                            /* 0x0001 */ unsigned char QueueReservedControlFlags : 6; /* bit position: 2 */
                        }; /* bitfield */
                        /* 0x0002 */ unsigned char QueueSize;
                        /* 0x0003 */ unsigned char QueueReserved;
                    }; /* size: 0x0003 */
                }; /* size: 0x0003 */
            }; /* size: 0x0004 */
            struct
            {
                /* 0x0000 */ unsigned char ThreadType;
                /* 0x0001 */ unsigned char ThreadReserved;
                union
                {
                    /* 0x0002 */ unsigned char ThreadControlFlags;
                    struct
                    {
                        struct /* bitfield */
                        {
                            /* 0x0002 */ unsigned char CycleProfiling : 1; /* bit position: 0 */
                            /* 0x0002 */ unsigned char CounterProfiling : 1; /* bit position: 1 */
                            /* 0x0002 */ unsigned char GroupScheduling : 1; /* bit position: 2 */
                            /* 0x0002 */ unsigned char AffinitySet : 1; /* bit position: 3 */
                            /* 0x0002 */ unsigned char Tagged : 1; /* bit position: 4 */
                            /* 0x0002 */ unsigned char EnergyProfiling : 1; /* bit position: 5 */
                            /* 0x0002 */ unsigned char SchedulerAssist : 1; /* bit position: 6 */
                            /* 0x0002 */ unsigned char ThreadReservedControlFlags : 1; /* bit position: 7 */
                        }; /* bitfield */
                        union
                        {
                            /* 0x0003 */ unsigned char DebugActive;
                            struct /* bitfield */
                            {
                                /* 0x0003 */ unsigned char ActiveDR7 : 1; /* bit position: 0 */
                                /* 0x0003 */ unsigned char Instrumented : 1; /* bit position: 1 */
                                /* 0x0003 */ unsigned char Minimal : 1; /* bit position: 2 */
                                /* 0x0003 */ unsigned char Reserved4 : 2; /* bit position: 3 */
                                /* 0x0003 */ unsigned char AltSyscall : 1; /* bit position: 5 */
                                /* 0x0003 */ unsigned char Emulation : 1; /* bit position: 6 */
                                /* 0x0003 */ unsigned char Reserved5 : 1; /* bit position: 7 */
                            }; /* bitfield */
                        }; /* size: 0x0001 */
                    }; /* size: 0x0002 */
                }; /* size: 0x0002 */
            }; /* size: 0x0004 */
            struct
            {
                /* 0x0000 */ unsigned char MutantType;
                /* 0x0001 */ unsigned char MutantSize;
                /* 0x0002 */ unsigned char DpcActive;
                /* 0x0003 */ unsigned char MutantReserved;
            }; /* size: 0x0004 */
        }; /* size: 0x0004 */
        /* 0x0004 */ long SignalState;
        /* 0x0008 */ struct _LIST_ENTRY WaitListHead;
    } DISPATCHER_HEADER, * PDISPATCHER_HEADER; /* size: 0x0018 */

    typedef struct _KEVENT
    {
        /* 0x0000 */ struct _DISPATCHER_HEADER Header;
    } KEVENT, * PKEVENT; /* size: 0x0018 */


    typedef struct _IOP_MC_BUFFER_ENTRY
    {
        USHORT Type;
        USHORT Reserved;
        ULONG Size;
        ULONG ReferenceCount;
        ULONG Flags;
        _LIST_ENTRY GlobalDataLink;
        PVOID Address;
        ULONG Length;
        CHAR AccessMode;
        ULONG MdlRef;
        struct _MDL* Mdl;
        KEVENT MdlRundownEvent;
        PULONG64 PfnArray;
        BYTE PageNodes[0x20];
    } IOP_MC_BUFFER_ENTRY, * PIOP_MC_BUFFER_ENTRY;


    typedef struct _IORING_OBJECT
    {
        /* 0x0000 */ short Type;
        /* 0x0002 */ short Size;
        /* 0x0008 */ struct _NT_IORING_INFO UserInfo;
        /* 0x0038 */ void* Section;
        /* 0x0040 */ struct _NT_IORING_SUBMISSION_QUEUE* SubmissionQueue;
        /* 0x0048 */ struct _MDL* CompletionQueueMdl;
        /* 0x0050 */ struct _NT_IORING_COMPLETION_QUEUE* CompletionQueue;
        /* 0x0058 */ unsigned __int64 ViewSize;
        /* 0x0060 */ long InSubmit;
        /* 0x0068 */ unsigned __int64 CompletionLock;
        /* 0x0070 */ unsigned __int64 SubmitCount;
        /* 0x0078 */ unsigned __int64 CompletionCount;
        /* 0x0080 */ unsigned __int64 CompletionWaitUntil;
        /* 0x0088 */ struct _KEVENT CompletionEvent;
        /* 0x00a0 */ unsigned char SignalCompletionEvent;
        /* 0x00a8 */ struct _KEVENT* CompletionUserEvent;
        /* 0x00b0 */ unsigned int RegBuffersCount;
        /* 0x00b8 */ struct _IOP_MC_BUFFER_ENTRY** RegBuffers;
        /* 0x00c0 */ unsigned int RegFilesCount;
        /* 0x00c8 */ void** RegFiles;
    } IORING_OBJECT, * PIORING_OBJECT; /* size: 0x00d0 */

    typedef struct _HIORING
    {
        HANDLE handle;
        NT_IORING_INFO Info;
        ULONG IoRingKernelAcceptedVersion;
        PVOID RegBufferArray;
        ULONG BufferArraySize;
        PVOID Unknown;
        ULONG FileHandlesCount;
        ULONG SubQueueHead;
        ULONG SubQueueTail;
    } _HIORING
        ;
} // namespace CVE_2023_21768