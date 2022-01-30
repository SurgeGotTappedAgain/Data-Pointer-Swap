#include "Memory.h"

__int64(__fastcall* original_function)(void*, void*, void*);
__int64 __fastcall hooked_function(void* a1, void* a2, void* a3)
{
	if (ExGetPreviousMode() != UserMode)
	{
		return original_function(a1, a2, a3);
	}

	if (!a1)
	{
		return original_function(a1, a2, a3);
	}

	WRITE_STRUCT* w = (WRITE_STRUCT*)a1;

	if (w->special != 0xDEAD)
	{
		return original_function(a1, a2, a3);
	}
	if (w->write)
	{
		if (!w->address || !w->target_pid || !w->size)
			return STATUS_INVALID_PARAMETER;

		PEPROCESS proc;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)w->target_pid, &proc)))
			return STATUS_INVALID_PARAMETER_1;

		SIZE_T bytes = 0;

		NTSTATUS status = MmCopyVirtualMemory(PsGetCurrentProcess(), w->buffer, proc, w->address, w->size, KernelMode, &bytes);

		if (!NT_SUCCESS(status))
			return STATUS_UNSUCCESSFUL;

		return STATUS_SUCCESS;
	}
	else if (w->read)
	{
		if (!w->address || !w->target_pid || !w->size)
			return STATUS_INVALID_PARAMETER;

		PEPROCESS proc;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)w->target_pid, &proc)))
			return STATUS_INVALID_PARAMETER_1;

		SIZE_T bytes = 0;

		NTSTATUS status = MmCopyVirtualMemory(proc, w->address, PsGetCurrentProcess(), w->buffer, w->size, KernelMode, &bytes);

		if (!NT_SUCCESS(status))
			return STATUS_UNSUCCESSFUL;

		return STATUS_SUCCESS;
	}
	else if (w->request_base)
	{
		PEPROCESS target_proc;
		PsLookupProcessByProcessId((HANDLE)w->target_pid, &target_proc);
		w->process_base = PsGetProcessSectionBaseAddress(target_proc);
		ObDereferenceObject(target_proc);
	}
	return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drv_obj, PUNICODE_STRING reg_pth)
{
	UNREFERENCED_PARAMETER(drv_obj);
	UNREFERENCED_PARAMETER(reg_pth);

	DbgPrintEx(0, 0, "[+] Driver Loaded");

	PVOID image_base = memory::GetSystemBaseModule("\\SystemRoot\\System32\\win32kbase.sys");
	if (!image_base)
	{
		DbgPrintEx(0, 0, "[+] Error Finding Image Base");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0, 0, "[+] Found Image Base");

	PBYTE FunctionAddress1 = memory::FindPatternWork(image_base, "\x74\x10\x4C\x8B\xC6\x48\x8B\xD5\xFF\x15\x00\x00\x00\x00", "xxxxxxxxxx????");
	if (!FunctionAddress1)
	{
		DbgPrintEx(0, 0, "[+] Error Finding Qword Pointer 1");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0, 0, "[+] Found Qword Pointer 1: 0x%llx", FunctionAddress1);

	UINT64 deref_pointer1 = (UINT64)(FunctionAddress1) - 0xA;
	deref_pointer1 = (UINT64)deref_pointer1 + *(PINT)((PBYTE)deref_pointer1 + 3) + 7;

	DbgPrintEx(0, 0, "[+] Derefed Pointer 1: 0x%llx", &deref_pointer1);

	if (NT_SUCCESS(memory::FindProcessByName("explorer.exe", &target)))
	{
		DbgPrintEx(0, 0, "[+] Found Explorer.exe: %p", target);

		KeAttachProcess(target);
		*(void**)&original_function = _InterlockedExchangePointer((void**)deref_pointer1, (void**)hooked_function);
		KeDetachProcess();

		DbgPrintEx(0, 0, "[+] Attached & Detached Target");
	}
	else
	{
		DbgPrintEx(0, 0, "[!] Failed To Find Explorer.exe");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0, 0, "[+] Swapped Qword Pointer");

	return STATUS_SUCCESS;
}