#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

extern int pid;
extern PVOID proc_base;

bool setup_comm();
DWORD get_pid(LPCWSTR process_name);
PVOID get_base(DWORD pid);

struct WRITE_STRUCT
{
	int special;
	bool read;
	bool write;
	bool request_base;
	int target_pid;
	void* base_address;
	void* address;
	void* buffer;
	void* output;
	void* process_base;

	size_t size;

	const char* mod_name;
};