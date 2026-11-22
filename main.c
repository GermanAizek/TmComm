#include "tmcomm.h"
#include <wdmsec.h>

// Unique GUID for device class (required for IoCreateDeviceSecure)
// {D8B9B732-2F1E-4E9B-987A-154A8BE1C9F2}
static const GUID GUID_DEVCLASS_TMCOMM = 
{ 0xd8b9b732, 0x2f1e, 0x4e9b, { 0x98, 0x7a, 0x15, 0x4a, 0x8b, 0xe1, 0xc9, 0xf2 } };

//
// Driver Unload routine
// Corresponds to GHIDRA FUN_000298b4
//
VOID TmCommUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLinkName;

    if (DriverObject->DeviceObject != NULL) {
        PTMCOMM_DEVICE_EXTENSION devExt = (PTMCOMM_DEVICE_EXTENSION)DriverObject->DeviceObject->DeviceExtension;
        if (devExt != NULL) {
            if (devExt->UnloadCallback != NULL) {
                typedef VOID (*PFN_UNLOAD_CALLBACK)(PVOID Context);
                PFN_UNLOAD_CALLBACK pfn = (PFN_UNLOAD_CALLBACK)devExt->UnloadCallback;
                pfn(devExt->UnloadContext);
            }
            if (devExt->ResourceInitialized) {
                ExDeleteResourceLite(&devExt->Resource);
                devExt->ResourceInitialized = FALSE;
            }
        }
    }

    RtlInitUnicodeString(&symbolicLinkName, TMCOMM_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&symbolicLinkName);

    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

//
// Dispatch routine for Create, Close, and DeviceControl
// Corresponds to GHIDRA FUN_00029728
//
NTSTATUS TmCommDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    PTMCOMM_DEVICE_EXTENSION devExt = (PTMCOMM_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;

    if (irpSp->MajorFunction == IRP_MJ_CREATE || irpSp->MajorFunction == IRP_MJ_CLOSE) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    if (irpSp->MajorFunction != IRP_MJ_DEVICE_CONTROL) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    ULONG ioctlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    switch (ioctlCode) {
    case IOCTL_TMCOMM_PROCESS_DISPATCH:
        status = TmCommHandleProcessDispatch(systemBuffer, inputLength, &information);
        break;

    case IOCTL_TMCOMM_FS_DISPATCH:
        status = TmCommHandleFsDispatch(systemBuffer, inputLength, &information);
        break;

    case IOCTL_TMCOMM_TRUEAPI_DISPATCH:
        status = TmCommHandleTrueApiDispatch(devExt, systemBuffer, inputLength, &information);
        break;

    case IOCTL_TMCOMM_XRAY_DISPATCH:
        status = TmCommHandleXrayDispatch(systemBuffer, inputLength, &information);
        break;

    case IOCTL_TMCOMM_HOOKS_DISPATCH:
        status = TmCommHandleHooksDispatch(systemBuffer, inputLength, &information);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    if (!NT_SUCCESS(status)) {
        information = 0;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

//
// Driver Entry point
// Corresponds to GHIDRA FUN_00029e08
//
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;

    // SDDL Security String:
    // D:P         -> DACL Protected
    // (A;;GA;;;SY)-> Allow Full Access to Local System
    // (A;;GA;;;BA)-> Allow Full Access to Built-in Administrators
    DECLARE_CONST_UNICODE_STRING(sddlSecureString, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    RtlInitUnicodeString(&deviceName, TMCOMM_DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLinkName, TMCOMM_DOS_DEVICE_NAME);

    status = IoCreateDeviceSecure(
        DriverObject,
        sizeof(TMCOMM_DEVICE_EXTENSION),
        &deviceName,
        TMCOMM_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddlSecureString,
        &GUID_DEVCLASS_TMCOMM,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    PTMCOMM_DEVICE_EXTENSION devExt = (PTMCOMM_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    RtlZeroMemory(devExt, sizeof(TMCOMM_DEVICE_EXTENSION));
    devExt->DeviceObject = deviceObject;
    ExInitializeResourceLite(&devExt->Resource);
    devExt->ResourceInitialized = TRUE;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = TmCommDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = TmCommDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TmCommDispatch;
    DriverObject->DriverUnload = TmCommUnload;

    return STATUS_SUCCESS;
}
