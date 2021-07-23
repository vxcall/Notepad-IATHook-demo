#include <iostream>
#include <Windows.h>
#include <string>
#include "Scanner.h"
#include "Process.h"

const char* targetFunc = "CreateFileW";

using CreateFileW_t = HANDLE(__stdcall*)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
CreateFileW_t OriginalCreateFileW = nullptr;

auto WINAPI hkCreateFileW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile) -> HANDLE
{
	MessageBox(NULL, "CreateFileW function has been hooked", "RESULT", MB_OK);
	return OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

auto HookIATEntry(void* hkfunction) -> void;

auto WINAPI hMain(LPVOID hModule) -> DWORD
{
	HookIATEntry((void*)hkCreateFileW);
	return TRUE;
}

auto HookIATEntry(void* hkfunction) -> void
{
	Scanner scanner(targetFunc);
	scanner.FindTargetIATEntry(0);

	if (*scanner.targetIATEntry == hkfunction)
	{
		return;
	}

	DWORD oldProtect, newProtect = PAGE_READWRITE;
	VirtualProtect(scanner.targetIATEntry, sizeof(LPVOID), newProtect, &oldProtect);

	OriginalCreateFileW = (CreateFileW_t)*scanner.targetIATEntry;
	*scanner.targetIATEntry = hkfunction;

	VirtualProtect(scanner.targetIATEntry, sizeof(LPVOID), oldProtect, &newProtect);
	return;
}

auto APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) -> BOOL
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);

		if (auto hThread = CreateThread(nullptr, 0, hMain, hModule, 0, nullptr); hThread)
		{
			CloseHandle(hThread);
		}
	}
	return TRUE;
}