#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include "Scanner.h"

const char *processName = "notepad.exe";
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

auto HookIATEntry(HANDLE hProc, void *hkfunction) -> void;

auto main() -> int
{
    PROCESSENTRY32 PE32{0};
    PE32.dwSize = sizeof(PE32);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateToolhelp32Snapshot failed: 0x%p\n", GetLastError);
        system("PAUSE");
        return 0;
    }
    DWORD PID = 0;
    BOOL bRet = Process32First(hSnap, &PE32);
    while (bRet)
    {
        if (!strcmp(processName, PE32.szExeFile))
        {
            PID = PE32.th32ProcessID;
            //std::cout << "[+] PID copied: " << PID << std::endl;
            break;
        }
        bRet = Process32Next(hSnap, &PE32);
    }

    CloseHandle(hSnap);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc)
    {
        printf("[-] OpenProcess failed: 0x%X\n", GetLastError());
        system("PAUSE");
        return 0;
    }

    HookIATEntry(hProc, (void *)hkCreateFileW);
    CloseHandle(hProc);
    return 0;
}

auto HookIATEntry(HANDLE hProc, void *hkfunction) -> void
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