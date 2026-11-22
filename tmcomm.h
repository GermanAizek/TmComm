#ifndef TMCOMM_H
#define TMCOMM_H

#include <ntddk.h>

#ifndef _MSC_VER
#ifndef __try
#define __try
#define __except(x) if (0)
#endif
#endif

#define TMCOMM_DEVICE_NAME           L"\\Device\\TmComm"
#define TMCOMM_DOS_DEVICE_NAME       L"\\DosDevices\\TmComm"
#define TMCOMM_DEVICE_TYPE           0x22

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_ALL_ACCESS
#define PROCESS_ALL_ACCESS 0x1FFFFF
#endif


// Main IOCTL definitions
#define IOCTL_TMCOMM_PROCESS_DISPATCH       0x90004027
#define IOCTL_TMCOMM_FS_DISPATCH            0x9000402B
#define IOCTL_TMCOMM_TRUEAPI_DISPATCH       0x90004033
#define IOCTL_TMCOMM_XRAY_DISPATCH          0x900040DF
#define IOCTL_TMCOMM_HOOKS_DISPATCH         0x900040E7

// Sub-operation codes for IOCTL_TMCOMM_PROCESS_DISPATCH (0x90004027)
#define TMCOMM_OP_GET_PROCESSES             0xC350
#define TMCOMM_OP_OPEN_PROCESS              0xC351
#define TMCOMM_OP_TERMINATE_PROCESS         0xC352
#define TMCOMM_OP_OPEN_PROCESS_LITE         0xC353

// Sub-operation codes for IOCTL_TMCOMM_FS_DISPATCH (0x9000402B)
#define TMCOMM_OP_CREATE_FILE               0xD480
#define TMCOMM_OP_READ_FILE                 0xD481
#define TMCOMM_OP_DELETE_FILE               0xD482
#define TMCOMM_OP_SET_INFO_FILE             0xD483
#define TMCOMM_OP_SET_FILE_SEC              0xD484
#define TMCOMM_OP_GET_FILE_SEC              0xD485

// Sub-operation codes for IOCTL_TMCOMM_TRUEAPI_DISPATCH (0x90004033)
#define TMCOMM_OP_GET_TRUEAPI_PTR           0xEA60
#define TMCOMM_OP_GET_UTIL_PTR              0xEA61
#define TMCOMM_OP_REGISTER_UNLOAD           0xEA62

// Sub-operation codes for IOCTL_TMCOMM_XRAY_DISPATCH (0x900040DF)
#define TMCOMM_OP_XRAY_READ_FILE            0x15F90
#define TMCOMM_OP_UPDATE_CORE               0x15F91

// Sub-operation codes for IOCTL_TMCOMM_HOOKS_DISPATCH (0x900040E7)
#define TMCOMM_OP_CHECK_ROUTINE             0x186A0
#define TMCOMM_OP_CHECK_OBJECT              0x186A1

#pragma pack(push, 1)

// Open Process request
typedef struct _TMCOMM_OPEN_PROCESS_REQUEST {
    ULONG OperationCode;     // +0x00
    ULONG Reserved04;        // +0x04
    ACCESS_MASK DesiredAccess; // +0x08
    ULONG ProcessId;         // +0x0C
    HANDLE ProcessHandle;    // +0x10
} TMCOMM_OPEN_PROCESS_REQUEST, *PTMCOMM_OPEN_PROCESS_REQUEST;

// Terminate Process request
typedef struct _TMCOMM_TERMINATE_PROCESS_REQUEST {
    ULONG OperationCode;     // +0x00
    ULONG ProcessId;         // +0x04
    NTSTATUS ExitStatus;     // +0x08
} TMCOMM_TERMINATE_PROCESS_REQUEST, *PTMCOMM_TERMINATE_PROCESS_REQUEST;

// File operation request
typedef struct _TMCOMM_FILE_REQUEST {
    ULONG OperationCode;     // +0x00
    ULONG Flags;             // +0x04
    WCHAR FilePath[260];     // +0x08
} TMCOMM_FILE_REQUEST, *PTMCOMM_FILE_REQUEST;

// Unload notification request
typedef struct _TMCOMM_UNLOAD_NOTIFY_REQUEST {
    ULONG OperationCode;     // +0x00
    PVOID CallbackRoutine;   // +0x04 / +0x08
    PVOID Context;           // +0x0C / +0x10
} TMCOMM_UNLOAD_NOTIFY_REQUEST, *PTMCOMM_UNLOAD_NOTIFY_REQUEST;

#pragma pack(pop)

// Device Extension
typedef struct _TMCOMM_DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
    PVOID UnloadCallback;
    PVOID UnloadContext;
    ERESOURCE Resource;
    BOOLEAN ResourceInitialized;
} TMCOMM_DEVICE_EXTENSION, *PTMCOMM_DEVICE_EXTENSION;

NTSYSAPI
NTSTATUS
NTAPI
ZwDeleteFile(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
);

// Function prototypes
// main.c
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD TmCommUnload;
DRIVER_DISPATCH TmCommDispatch;

// process.c
NTSTATUS TmCommHandleProcessDispatch(
    _Inout_ PVOID SystemBuffer,
    _In_ ULONG InputLength,
    _Out_ PULONG_PTR Information
);

NTSTATUS TmCommOpenProcess(
    _Inout_ PTMCOMM_OPEN_PROCESS_REQUEST Request,
    _Out_ PULONG_PTR Information
);

NTSTATUS TmCommTerminateProcess(
    _In_ PTMCOMM_TERMINATE_PROCESS_REQUEST Request
);

// file.c
NTSTATUS TmCommHandleFsDispatch(
    _Inout_ PVOID SystemBuffer,
    _In_ ULONG InputLength,
    _Out_ PULONG_PTR Information
);

NTSTATUS TmCommDeleteFile(
    _In_ PCWSTR FilePath
);

// trueapi.c
NTSTATUS TmCommHandleTrueApiDispatch(
    _In_ PTMCOMM_DEVICE_EXTENSION DeviceExtension,
    _Inout_ PVOID SystemBuffer,
    _In_ ULONG InputLength,
    _Out_ PULONG_PTR Information
);

// xray.c
NTSTATUS TmCommHandleXrayDispatch(
    _Inout_ PVOID SystemBuffer,
    _In_ ULONG InputLength,
    _Out_ PULONG_PTR Information
);

NTSTATUS TmCommHandleHooksDispatch(
    _Inout_ PVOID SystemBuffer,
    _In_ ULONG InputLength,
    _Out_ PULONG_PTR Information
);

#endif // TMCOMM_H
