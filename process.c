#include "tmcomm.h"

//
// Opens a handle to specified process
// Corresponds to GHIDRA IoControlOpenProcess (FUN_0002d184)
//
NTSTATUS TmCommOpenProcess(
    _Inout_ PTMCOMM_OPEN_PROCESS_REQUEST Request,
    _Out_ PULONG_PTR Information
)
{
    *Information = 0;
    if (Request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;

    // FIX: Block opening protected system processes (PID <= 4)
    if (Request->ProcessId <= 4) {
        return STATUS_ACCESS_DENIED;
    }

    // FIX: Disallow dangerous write, injection, and elevation access rights
    if ((Request->DesiredAccess & TMCOMM_DISALLOWED_PROCESS_ACCESS) != 0) {
        return STATUS_ACCESS_DENIED;
    }

    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)Request->ProcessId;
    clientId.UniqueThread = NULL;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    HANDLE processHandle = NULL;
    NTSTATUS status = ZwOpenProcess(
        &processHandle,
        Request->DesiredAccess,
        &objAttr,
        &clientId
    );

    if (NT_SUCCESS(status)) {
        Request->ProcessHandle = processHandle;
        *Information = sizeof(TMCOMM_OPEN_PROCESS_REQUEST);
    }

    return status;
}

//
// Terminates specified process
// Corresponds to GHIDRA IoControlTerminateProcess (FUN_0002d094)
//
NTSTATUS TmCommTerminateProcess(
    _In_ PTMCOMM_TERMINATE_PROCESS_REQUEST Request
)
{
    if (Request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // FIX: Prohibit terminating critical system and root processes
    if (Request->ProcessId <= 4) {
        return STATUS_ACCESS_DENIED;
    }

    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;

    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)Request->ProcessId;
    clientId.UniqueThread = NULL;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    HANDLE processHandle = NULL;
    NTSTATUS status = ZwOpenProcess(
        &processHandle,
        PROCESS_TERMINATE,
        &objAttr,
        &clientId
    );

    if (NT_SUCCESS(status)) {
        status = ZwTerminateProcess(processHandle, Request->ExitStatus);
        ZwClose(processHandle);
    }

    return status;
}

//
// Handles process sub-dispatch table (IOCTL 0x90004027)
//
NTSTATUS TmCommHandleProcessDispatch(
    _Inout_ PVOID SystemBuffer,
    _In_ ULONG InputLength,
    _Out_ PULONG_PTR Information
)
{
    *Information = 0;
    if (SystemBuffer == NULL || InputLength < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }

    PULONG pOpCode = (PULONG)SystemBuffer;
    switch (*pOpCode) {
    case TMCOMM_OP_OPEN_PROCESS:
    case TMCOMM_OP_OPEN_PROCESS_LITE:
        if (InputLength >= sizeof(TMCOMM_OPEN_PROCESS_REQUEST)) {
            return TmCommOpenProcess((PTMCOMM_OPEN_PROCESS_REQUEST)SystemBuffer, Information);
        }
        return STATUS_INVALID_PARAMETER;

    case TMCOMM_OP_TERMINATE_PROCESS:
        if (InputLength >= sizeof(TMCOMM_TERMINATE_PROCESS_REQUEST)) {
            return TmCommTerminateProcess((PTMCOMM_TERMINATE_PROCESS_REQUEST)SystemBuffer);
        }
        return STATUS_INVALID_PARAMETER;

    case TMCOMM_OP_GET_PROCESSES:
        *Information = sizeof(ULONG);
        return STATUS_SUCCESS;

    default:
        break;
    }

    return STATUS_INVALID_PARAMETER;
}
