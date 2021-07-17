#include <iostream>
#include <Windows.h>
#include <string>
#include "Scanner.h"
#include "Process.h"

const char *targetFunc = "CreateFileW";

using CreateFileW_t = HANDLE(__stdcall *)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
CreateFileW_t OriginalCreateFileW = nullptr;

HANDLE __stdcall hkCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    MessageBox(NULL, "Function has been hooked", "RESULT", MB_OK);
    return OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

auto HookIATEntry(HANDLE &hProc, void *hkfunction) -> void;

auto main() -> int
{
    HANDLE hProc = Process::GetProcessHandle("notepad.exe");
    HookIATEntry(hProc, (void *)hkCreateFileW);
    CloseHandle(hProc);
    return 0;
}

auto HookIATEntry(HANDLE &hProc, void *hkfunction) -> void
{
    Scanner scanner(targetFunc);
    scanner.FindTargetIATEntry(0);

    if (*scanner.targetIATEntry == hkfunction)
    {
        std::cout << "same" << std::endl;
        return;
    }

    DWORD oldProtect, newProtect = PAGE_READWRITE;
    VirtualProtectEx(hProc, scanner.targetIATEntry, sizeof(LPVOID), newProtect, &oldProtect);

    OriginalCreateFileW = (CreateFileW_t)*scanner.targetIATEntry;
    WriteProcessMemory(hProc, *scanner.targetIATEntry, hkfunction, sizeof(hkfunction), NULL);

    VirtualProtectEx(hProc, scanner.targetIATEntry, sizeof(LPVOID), oldProtect, &newProtect);
    return;
}
