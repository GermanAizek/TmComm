#include "tmcomm.h"

//
// Handles TrueApi sub-dispatch table (IOCTL 0x90004033)
// Corresponds to GHIDRA IoControlGetTrueAPIPointer / IoControlRegisterUnloadNotify
//
NTSTATUS TmCommHandleTrueApiDispatch(
    _In_ PTMCOMM_DEVICE_EXTENSION DeviceExtension,
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
    case TMCOMM_OP_REGISTER_UNLOAD:
        if (InputLength >= sizeof(TMCOMM_UNLOAD_NOTIFY_REQUEST)) {
            PTMCOMM_UNLOAD_NOTIFY_REQUEST req = (PTMCOMM_UNLOAD_NOTIFY_REQUEST)SystemBuffer;

            // FIX: Disallow registering user-mode callbacks to prevent arbitrary kernel execution
            if (req->CallbackRoutine == NULL ||
                (ULONG_PTR)req->CallbackRoutine <= (ULONG_PTR)MM_HIGHEST_USER_ADDRESS) {
                return STATUS_ACCESS_DENIED;
            }

            DeviceExtension->UnloadCallback = req->CallbackRoutine;
            DeviceExtension->UnloadContext = req->Context;
            *Information = sizeof(TMCOMM_UNLOAD_NOTIFY_REQUEST);
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_PARAMETER;

    case TMCOMM_OP_GET_TRUEAPI_PTR:
    case TMCOMM_OP_GET_UTIL_PTR:
        *Information = sizeof(ULONG);
        return STATUS_SUCCESS;

    default:
        break;
    }

    return STATUS_INVALID_PARAMETER;
}
