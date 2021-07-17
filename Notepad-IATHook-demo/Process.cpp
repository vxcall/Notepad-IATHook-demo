#include "Process.h"

auto Process::GetProcessHandle(const char *processName) -> HANDLE
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
    return hProc;
}