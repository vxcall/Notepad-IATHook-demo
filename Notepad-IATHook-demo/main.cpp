#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include "Scanner.h"

const char *processName = "notepad.exe";
const char *targetFunc = "CreateFileW";

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
            std::cout << "[+] PID copied: " << PID << std::endl;
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

    HookIATEntry(hProc, nullptr);
    CloseHandle(hProc);
}

auto HookIATEntry(HANDLE hProc, void *hkfunction) -> void
{
    Scanner scanner(targetFunc);
    scanner.FindDlls(0);
    std::cout << scanner.targetIATEntry << std::endl;

    if (*scanner.targetIATEntry == hkfunction)
    {
        return;
    }

    DWORD oldProtect;
    VirtualProtectEx(hProc, scanner.targetIATEntry, sizeof(LPVOID), PAGE_READWRITE, &oldProtect);

    WriteProcessMemory(hProc, *scanner.targetIATEntry, hkfunction, sizeof(hkfunction), NULL);

    VirtualProtectEx(hProc, scanner.targetIATEntry, sizeof(LPVOID), oldProtect, NULL);
}