#include<ntifs.h>
#include<ntddk.h>

#define READ CTL_CODE(FILE_DEVICE_UNKNOWN,4396,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define WRITE CTL_CODE(FILE_DEVICE_UNKNOWN,4397,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define CALL CTL_CODE(FILE_DEVICE_UNKNOWN,4398,METHOD_BUFFERED,FILE_ANY_ACCESS)

struct Read {
	DWORD64 PID;
	PVOID64 sourceAddress;
	SIZE_T size;
};

struct Write {
	DWORD64 PID;
	PVOID64 sourceAddress;
	SIZE_T size;
	PVOID64 targetAddress;
};

struct Call {
	DWORD64 PID;
	int (*address)(int);
	DWORD32 param;
};

UNICODE_STRING DeviceName=RTL_CONSTANT_STRING(L"\\Device\\killurself");
UNICODE_STRING symLinkName=RTL_CONSTANT_STRING(L"\\??\\killurself");
PDEVICE_OBJECT DeviceObject=NULL;

void unload(PDRIVER_OBJECT obj) {
	IoDeleteSymbolicLink(&symLinkName);
	IoDeleteDevice(DeviceObject);
	DbgPrint("[killurself] Unload driver successfully");
}

void CopyProcessMemory(PEPROCESS process,PVOID64 sourceAddress,SIZE_T size,PVOID64 targetAddress)
{
	KAPC_STATE state;
	KeStackAttachProcess(process,&state);

	if(MmIsAddressValid(sourceAddress))
		memcpy(targetAddress,sourceAddress,size);

	KeUnstackDetachProcess(&state);
}

int CallFunction(PEPROCESS process, int (*address)(int), int param) {
	KAPC_STATE state;
	KeStackAttachProcess(process, &state);

	int buffer = address(param);

	KeUnstackDetachProcess(&state);

	return buffer;
}

NTSTATUS DispatchDevCTL(PDEVICE_OBJECT DeviceObject,PIRP Irp) {
	NTSTATUS status=STATUS_INVALID_DEVICE_REQUEST;

	PIO_STACK_LOCATION stack=IoGetCurrentIrpStackLocation(Irp);
	PVOID buffer=Irp->AssociatedIrp.SystemBuffer;
	ULONG CTLcode=stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG uInSize=stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG uOutSize=stack->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG ioinfo=0;
	switch(CTLcode) {
		case READ: {
			struct Read read=*(struct Read*)buffer;
			PEPROCESS process;
			HANDLE pid=(HANDLE)read.PID;
			PVOID64 sourceAddress=read.sourceAddress;
			SIZE_T size=read.size;

			PsLookupProcessByProcessId(pid,&process);

			PVOID temp = ExAllocatePool(NonPagedPool, size);
			if (temp != NULL) {
				RtlFillMemory(temp, size, 0);

				CopyProcessMemory(process, sourceAddress, size, temp);

				RtlCopyMemory(buffer, temp, size);
			}
			ExFreePool(temp);

			ioinfo = size;
			status=STATUS_SUCCESS;
			break;
		}
		case WRITE: {
			struct Write write = *(struct Write*)buffer;
			PEPROCESS process;
			HANDLE pid = (HANDLE)write.PID;
			PVOID64 sourceAddress = write.sourceAddress;
			SIZE_T size = write.size;
			PVOID64 targetAddress = write.targetAddress;

			PsLookupProcessByProcessId(pid,&process);


			PVOID temp = ExAllocatePool(NonPagedPool, size);
			if (temp != NULL) {
				RtlFillMemory(temp, size, 0);
				RtlCopyMemory(temp, sourceAddress, size);
				CopyProcessMemory(process, temp, size, targetAddress);
			}
			ExFreePool(temp);

			status=STATUS_SUCCESS;
			break;
		}
		case CALL: {
			struct Call call = *(struct Call*)buffer;

			PEPROCESS process;
			HANDLE pid = (HANDLE)call.PID;
			int (*address)(int)= call.address;
			DWORD32 param = call.param;

			PsLookupProcessByProcessId(pid, &process);

			int ret = CallFunction(process, address, param);

			*(int*)buffer = ret;
			ioinfo = 4;
			status = STATUS_SUCCESS;
			break;
		}
		default: {
			status=STATUS_UNSUCCESSFUL;
			break;
		}
	}

	Irp->IoStatus.Information=ioinfo;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	return status;
}

NTSTATUS Create(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("[killurself] create");
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS Close(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("[killurself] close");
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING regPath) {
	DbgPrint("%wZ",regPath);
	object->DriverUnload=unload;

	NTSTATUS status=IoCreateDevice(object,0,&DeviceName,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&DeviceObject);
	if(!NT_SUCCESS(status)) {
		DbgPrint("[killurself] Create device failed");
		IoDeleteDevice(DeviceObject);
		return status;
	}

	status=IoCreateSymbolicLink(&symLinkName,&DeviceName);
	if(!NT_SUCCESS(status)) {
		DbgPrint("[killurself] Create symbolic link failed");
		IoDeleteSymbolicLink(&symLinkName);
		return status;
	}
	object->MajorFunction[IRP_MJ_CREATE] = Create;
	object->MajorFunction[IRP_MJ_CLOSE] = Close;
	object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDevCTL;
	return STATUS_SUCCESS;
}