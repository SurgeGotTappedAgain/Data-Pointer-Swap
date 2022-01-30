#pragma once
#include "Memory.h"

int main()
{
	if (!setup_comm())
	{
		std::cout << "[!] Failed To Setup Communication" << std::endl;
		return 0;
	}

	std::cout << "[+] Communication Established" << std::endl;

	pid = get_pid(L"notepad.exe");

	if (!pid)
	{
		std::cout << "[!] Failed To Get PID" << std::endl;
		return 0;
	}

	std::cout << "[+] PID: " << pid << std::endl;

	std::getchar();
	return 0;

}