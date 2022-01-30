#include "Memory.h"

int pid;
PVOID proc_base;
void(__fastcall* FunctionPTR)(void* a1, void* a2, void* a3);

bool setup_comm()
{
	auto ntdll_base = LoadLibraryA("win32u.dll");
	if (!ntdll_base) {
		return FALSE;
	}
	std::cout << "[+] Found win32u.dll: " << ntdll_base << std::endl;

	auto function_addr = GetProcAddress(ntdll_base, "NtDCompositionSetChildRootVisual");
	if (!function_addr) {
		return FALSE;
	}

	*(void**)&FunctionPTR = function_addr;

	std::cout << "[+] Found Function Address: " << function_addr << std::endl;

	return &FunctionPTR;
}

DWORD get_pid(LPCWSTR process_name) 
{
	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	DWORD pid = NULL;

	if (handle == INVALID_HANDLE_VALUE)
		return pid;

	PROCESSENTRY32W entry = { 0 };
	entry.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(handle, &entry)) {
		if (!_wcsicmp(process_name, entry.szExeFile)) {
			pid = entry.th32ProcessID;
		}
		else while (Process32NextW(handle, &entry)) {
			if (!_wcsicmp(process_name, entry.szExeFile)) {
				pid = entry.th32ProcessID;
			}
		}
	}

	CloseHandle(handle);
	return pid;
}

// test this out
PVOID get_base(DWORD pid)
{
	WRITE_STRUCT request = {};
	SecureZeroMemory(&request, sizeof(WRITE_STRUCT));

	request.special = 0xDEAD;
	request.write = FALSE;
	request.read = FALSE;
	request.request_base = TRUE;
	request.target_pid = pid;

	FunctionPTR(&request, 0, 0);
	return request.process_base;
}