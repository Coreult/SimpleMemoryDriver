#include <ntddk.h>
#include "Memory.h"
//#include "SSDT.h"

#define SYMBOL_NAME L"\\DosDevices\\AKATSUKI"  
#define DEVICE_NAME L"\\Device\\AKATSUKI"  

#define IOCTL_DEBUG_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)  
#define IOCTL_SET_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x703, METHOD_BUFFERED, FILE_ANY_ACCESS) 
#define IOCTL_GET_MOUDELBASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x705, METHOD_BUFFERED, FILE_ANY_ACCESS) 
#define IOCTL_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x701, METHOD_BUFFERED, FILE_ANY_ACCESS) 
#define IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x702, METHOD_BUFFERED, FILE_ANY_ACCESS) 

PEPROCESS EPROCESS = NULL;


VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	KdPrint(("[AKATSUKI]Driver Unload!\n"));
	if (EPROCESS)
	{
		ObDereferenceObject(EPROCESS);
	}
	UNICODE_STRING SymbolLink;
	RtlInitUnicodeString(&SymbolLink, SYMBOL_NAME);
	IoDeleteSymbolicLink(&SymbolLink);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInSize;
	ULONG uOutSize;
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (uIoControlCode)
	{
	case IOCTL_SET_PROCESS:
	{
		UINT32 PID = 0;
		RtlCopyMemory(&PID, pIoBuffer, sizeof(UINT32));
		status = PsLookupProcessByProcessId((HANDLE)PID, &EPROCESS);
		break;
	}
	case IOCTL_GET_MOUDELBASE:
	{
		UINT64 Module = 0;
		KeAttachProcess(EPROCESS);
		Module = (UINT64)PsGetProcessSectionBaseAddress(EPROCESS);
		KeDetachProcess();
		KdPrint(("[AKATSUKI]Moudel Base:%d %d\n", &MoudelBase,MoudelBase));
		if (Module > 0)
		{
			RtlCopyMemory(pIoBuffer, &Module, sizeof(PVOID));
			status = STATUS_SUCCESS;
		}
		else
		{
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case IOCTL_READ_MEMORY: 
	{
		PReadMemory pRead = (PReadMemory)pIoBuffer;
		KdPrint(("[AKATSUKI]Read Address:%d\n",pRead->Address));
		KdPrint(("[AKATSUKI]Read Lenth:%d\n", pRead->Lenth));
		status = RPM(EPROCESS,(PVOID)pRead->Address,pIoBuffer,pRead->Lenth);
		break;
	}
	case IOCTL_WRITE_MEMORY:
	{
		PWriteMemory pWrite = (PWriteMemory)pIoBuffer;
		KdPrint(("[AKATSUKI]Read Address:%d\n", pWrite->Address));
		KdPrint(("[AKATSUKI]Read Lenth:%d\n", pWrite->Lenth));
		KdPrint(("[AKATSUKI]Read pData:%d\n", pWrite->pData));
		status = WPM(EPROCESS, (PVOID)pWrite->Address, (PVOID)pWrite->pData, pWrite->Lenth);
		break;
	}

	}
	if (status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = uOutSize;
	else
		pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryString) 
{
	KdPrint(("[AKATSUKI]Driver Load!\n"));
	UNREFERENCED_PARAMETER(pRegistryString);
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING SymbolLink;
	UNICODE_STRING DeviceObject;
	PDEVICE_OBJECT pDeviceObject;

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObject->DriverUnload = DriverUnload;

	RtlInitUnicodeString(&DeviceObject, DEVICE_NAME);
	status = IoCreateDevice(pDriverObject, 0, &DeviceObject, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	RtlInitUnicodeString(&SymbolLink, SYMBOL_NAME);
	status = IoCreateSymbolicLink(&SymbolLink, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDeviceObject);
		return status;
	}
	KdPrint(("[AKATSUKI]Driver Init is fine!\n"));
	return STATUS_SUCCESS;

}

