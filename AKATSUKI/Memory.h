#pragma once
#include <ntddk.h>

#pragma pack(4)
typedef struct _ReadMemory
{
	UINT64 Address;//4+8=12
	UINT32 Lenth;//4+8+4=16
} ReadMemory, *PReadMemory;

typedef struct _WriteMemory
{
	UINT64 Address;//4+8=12
	UINT32 pData;//4+8+4=16
	UINT32 Lenth;//4+8+4+4=20
} WriteMemory, *PWriteMemory;
#pragma pack()

NTSTATUS NTAPI MmCopyVirtualMemory(IN PEPROCESS SourceProcess,IN PVOID SourceAddress,IN PEPROCESS TargetProcess,OUT PVOID TargetAddress,IN SIZE_T BufferSize,IN KPROCESSOR_MODE PreviousMode,OUT PSIZE_T ReturnSize);
NTSTATUS PsLookupProcessByProcessId(__in HANDLE ProcessId, __deref_out PEPROCESS *Process);
NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);
NTKERNELAPI VOID NTAPI KeAttachProcess(__in PEPROCESS Process);
NTKERNELAPI VOID NTAPI KeDetachProcess();
NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);


NTSTATUS MyReadMemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size);
NTSTATUS MyWriteMemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size);
NTSTATUS MyCopyMemory(PEPROCESS DstProcess, PVOID DstAddress, PEPROCESS SrcProcess, PVOID SrcAddress, SIZE_T size);
PVOID GetMoudelAddress(PEPROCESS pEPROCESS, PUNICODE_STRING pMoudelName);
PVOID GetMoudelSize(PEPROCESS pEPROCESS, PUNICODE_STRING pMoudelName);
NTSTATUS RPM(PEPROCESS process, PVOID Address, PVOID Buffer, SIZE_T size);
NTSTATUS WPM(PEPROCESS Process, PVOID Address, PVOID pData, SIZE_T size);