#include "tmcomm.h"

//
// Handles XrayApi sub-dispatch table (IOCTL 0x900040DF)
// Corresponds to GHIDRA XrayApi handlers
//
NTSTATUS TmCommHandleXrayDispatch(
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
    case TMCOMM_OP_XRAY_READ_FILE:
    case TMCOMM_OP_UPDATE_CORE:
        *Information = sizeof(ULONG);
        return STATUS_SUCCESS;

    default:
        break;
    }

    return STATUS_INVALID_PARAMETER;
}

//
// Handles system hook inspection sub-dispatch table (IOCTL 0x900040E7)
// Corresponds to GHIDRA TMXMSCheckSystemRoutine handlers
//
NTSTATUS TmCommHandleHooksDispatch(
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
    case TMCOMM_OP_CHECK_ROUTINE:
    case TMCOMM_OP_CHECK_OBJECT:
        *Information = sizeof(ULONG);
        return STATUS_SUCCESS;

    default:
        break;
    }

    return STATUS_INVALID_PARAMETER;
}
