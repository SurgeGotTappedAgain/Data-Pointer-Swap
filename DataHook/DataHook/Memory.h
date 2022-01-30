#pragma once
#include "Imports.h"

PEPROCESS target;
extern "C" NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);
extern "C" __declspec(dllimport) PLIST_ENTRY NTAPI PsLoadedModuleList;
extern "C" NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineNam);
extern "C" NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

namespace memory
{
	PVOID GetSystemBaseModule(const char* module_name)
	{
		ULONG bytes = 0;
		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

		if (!bytes) return 0;

		PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x504D5448);

		status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

		if (!NT_SUCCESS(status)) return 0;

		PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
		PVOID module_base = 0, module_size = 0;

		for (ULONG i = 0; i < modules->NumberOfModules; i++)
		{
			if (strcmp((char*)module[i].FullPathName, module_name) == 0)
			{
				DbgPrintEx(0, 0, "[+] Looping Module List");
				module_base = module[i].ImageBase;
				module_size = (PVOID)module[i].ImageSize;
				break;
			}
		}

		if (modules) ExFreePoolWithTag(modules, 0);
		if (module_base <= 0) return 0;
		return module_base;
	}

	NTSTATUS FindProcessByName(CHAR* process_name, PEPROCESS* process)
	{
		PEPROCESS sys_process = PsInitialSystemProcess;
		PEPROCESS cur_entry = sys_process;
		CHAR image_name[15];

		do
		{
			RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)cur_entry + 0x5a8), sizeof(image_name));

			if (strstr(image_name, process_name))
			{
				DWORD active_threads;
				RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)cur_entry + 0x5f0), sizeof(active_threads));
				if (active_threads)
				{
					*process = cur_entry;
					return STATUS_SUCCESS;
				}
			}

			PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(cur_entry) + 0x448);
			cur_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

		} while (cur_entry != sys_process);

		return STATUS_NOT_FOUND;
	}


	BOOLEAN data_compare(const BYTE* pData, const BYTE* bMask, const char* szMask)
	{
		for (; *szMask; ++szMask, ++pData, ++bMask)
			if (*szMask == 'x' && *pData != *bMask)
				return 0;
		return (*szMask) == 0;
	}


	PIMAGE_NT_HEADERS getHeader(PVOID module)
	{
		return (PIMAGE_NT_HEADERS)((PBYTE)module + PIMAGE_DOS_HEADER(module)->e_lfanew);
	}

	PBYTE FindPattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask)
	{

		auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
		{
			for (auto x = buffer; *mask; pattern++, mask++, x++)
			{
				auto addr = *(BYTE*)(pattern);
				if (addr != *x && *mask != '?')
					return FALSE;
			}

			return TRUE;
		};

		for (auto x = 0; x < size - strlen(mask); x++) 
		{

			auto addr = (PBYTE)module + x;
			if (checkMask(addr, pattern, mask))
				return addr;
		}

		return NULL;
	}

	PBYTE FindPatternWork(PVOID base, LPCSTR pattern, LPCSTR mask)
	{

		auto header = getHeader(base);
		auto section = IMAGE_FIRST_SECTION(header);

		for (auto x = 0; x < header->FileHeader.NumberOfSections; x++, section++)
		{

			if (!memcmp(section->Name, ".text", 5) || !memcmp(section->Name, "PAGE", 4))
			{
				auto addr = FindPattern((PBYTE)base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
				if (addr) {
					//DbgPrintEx(0, 0, "[+] Found in Section -> [ %s ]", section->Name);
					return addr;
				}
			}
		}

		return NULL;
	}
}