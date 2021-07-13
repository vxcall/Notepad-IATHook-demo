#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

const std::string processName = "notepad.exe";

int main()
{
    PROCESSENTRY32 PE32{0};
    PE32.dwSize = sizeof(PE32);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateToolhelp32Snapshot failed: 0x%X\n", GetLastError);
        system("PAUSE");
        return 0;
    }
    DWORD PID = 0;
    BOOL bRet = Process32First(hSnap, &PE32);
    while (bRet)
    {
        if (!strcmp(processName.c_str(), PE32.szExeFile))
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

    HMODULE hModule;
    BOOL err = GetModuleHandleEx(0, 0, &hModule);
    std::cout << "[+] module handle: 0x" << std::hex << hModule << std::endl;

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    DWORD dosBase = reinterpret_cast<DWORD>(pDosHeader);
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(dosBase + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeaders->OptionalHeader;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(dosBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    char *dllName = reinterpret_cast<char *>(dosBase + (pImportDescriptor)->Name);
    std::cout << dllName << std::endl;

    DWORD *ILTBase = reinterpret_cast<DWORD *>(dosBase + pImportDescriptor->OriginalFirstThunk); //Import lookup table is somewhere on the memory and OriginalFirstThunk tells you the relative location.
    PIMAGE_IMPORT_BY_NAME dllInfo = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(dosBase + *ILTBase);
    std::cout << dllInfo->Name << std::endl;
}