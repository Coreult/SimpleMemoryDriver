#include <ntddk.h>
#include <Memory.h>
NTSTATUS RPM(PEPROCESS process, PVOID Address, PVOID Buffer, SIZE_T size)
{
	SIZE_T  bytes;
	__try
	{
		if (NT_SUCCESS(MmCopyVirtualMemory(process, Address, PsGetCurrentProcess(), Buffer, size, KernelMode, &bytes)))
			return STATUS_SUCCESS;
		else
			return STATUS_UNSUCCESSFUL;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS WPM(PEPROCESS Process, PVOID Address, PVOID pData, SIZE_T size)
{
	SIZE_T bytes;
	__try
	{
		if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), pData, Process, Address, size, KernelMode, &bytes)))
		{
			return STATUS_SUCCESS;
		}

		else
		{
			return STATUS_UNSUCCESSFUL;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNSUCCESSFUL;
	}
}
