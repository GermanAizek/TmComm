#include "tmcomm.h"

//
// Validates file path to prevent arbitrary deletion of system files (CVE-2019-18187 / CVE-2020-24556)
//
BOOLEAN TmCommValidateFilePath(
    _In_ PCWSTR FilePath
)
{
    if (FilePath == NULL || FilePath[0] == 0) {
        return FALSE;
    }

    // Check for directory traversal
    if (wcsstr(FilePath, L"..") != NULL) {
        return FALSE;
    }

    // Prohibit targeting critical system paths
    if (wcsstr(FilePath, L"\\Windows\\System32") != NULL ||
        wcsstr(FilePath, L"\\SystemRoot") != NULL ||
        wcsstr(FilePath, L"\\Windows") != NULL ||
        wcsstr(FilePath, L"pagefile.sys") != NULL ||
        wcsstr(FilePath, L"ntoskrnl.exe") != NULL) {
        return FALSE;
    }

    return TRUE;
}

//
// Deletes a file on disk
// Corresponds to GHIDRA IoControlDeleteFileIRP (FUN_0002ad14)
//
NTSTATUS TmCommDeleteFile(
    _In_ PCWSTR FilePath
)
{
    if (FilePath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // FIX: Validate file path and block deletion of critical OS files
    if (!TmCommValidateFilePath(FilePath)) {
        return STATUS_ACCESS_DENIED;
    }

    UNICODE_STRING uPath;
    OBJECT_ATTRIBUTES objAttr;

    RtlInitUnicodeString(&uPath, FilePath);
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    return ZwDeleteFile(&objAttr);
}

//
// Handles filesystem sub-dispatch table (IOCTL 0x9000402B)
//
NTSTATUS TmCommHandleFsDispatch(
    _Inout_ PVOID SystemBuffer,
    _In_ ULONG InputLength,
    _Out_ PULONG_PTR Information
)
{
    *Information = 0;
    if (SystemBuffer == NULL || InputLength < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }

    PTMCOMM_FILE_REQUEST req = (PTMCOMM_FILE_REQUEST)SystemBuffer;
    switch (req->OperationCode) {
    case TMCOMM_OP_DELETE_FILE:
        if (InputLength >= sizeof(TMCOMM_FILE_REQUEST)) {
            return TmCommDeleteFile(req->FilePath);
        }
        return STATUS_INVALID_PARAMETER;

    case TMCOMM_OP_CREATE_FILE:
    case TMCOMM_OP_READ_FILE:
    case TMCOMM_OP_SET_INFO_FILE:
    case TMCOMM_OP_SET_FILE_SEC:
    case TMCOMM_OP_GET_FILE_SEC:
        *Information = sizeof(ULONG);
        return STATUS_SUCCESS;

    default:
        break;
    }

    return STATUS_INVALID_PARAMETER;
}
