#include "tmcomm.h"

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

    RtlInitUnicodeString(&deviceName, TMCOMM_DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLinkName, TMCOMM_DOS_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        sizeof(TMCOMM_DEVICE_EXTENSION),
        &deviceName,
        TMCOMM_DEVICE_TYPE,
        0,
        FALSE,
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
