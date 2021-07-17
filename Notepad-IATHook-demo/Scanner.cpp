#include "Scanner.h"

Scanner::~Scanner()
{
    this->ReleaseModuleHandles();
}

auto Scanner::ReleaseModuleHandles() -> void
{
    for (auto &hModule : this->moduleHandles)
    {
        CloseHandle(hModule);
    }
}

auto Scanner::IsScaned(std::string &candidate) -> bool
{
    for (auto &scaned : this->scanedDllName)
    {
        if (candidate == scaned)
        {
            return true;
        }
    }
    this->scanedDllName.push_back(candidate);
    return false;
}

auto Scanner::FindTargetIATEntry(const char *moduleName) -> void
{
    static bool found = false;

    HMODULE hModule;
    BOOL err = GetModuleHandleEx(0, moduleName, &hModule);
    if (!err)
    {
        this->moduleHandles.push_back(hModule);
    }

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    DWORD dosBase = reinterpret_cast<DWORD>(pDosHeader);
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(dosBase + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeaders->OptionalHeader;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(dosBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; pImportDescriptor->Name != NULL; ++pImportDescriptor)
    {
        char *dllName = reinterpret_cast<char *>(dosBase + pImportDescriptor->Name);

        if (found == true)
        {
            return;
        }
        if (std::string(dllName) != "" && !IsScaned(std::string(dllName)))
        {
            //std::cout << dllName << std::endl;
            DWORD *ILTBase = reinterpret_cast<DWORD *>(dosBase + pImportDescriptor->OriginalFirstThunk); //Import lookup table pointer is somewhere on the memory and OriginalFirstThunk tells you the relative location.

            for (int i = 0; *(ILTBase + i) != NULL; ++i)
            {
                PIMAGE_IMPORT_BY_NAME dllInfo = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(dosBase + *(ILTBase + i));
                if (!strcmp(dllInfo->Name, this->targetFunc))
                {
                    found = true;
                    this->targetIATEntry = i + reinterpret_cast<void **>(dosBase + pImportDescriptor->FirstThunk);
                    //std::cout << dllInfo->Name << std::endl;
                }
            }
            FindTargetIATEntry(dllName);
        }
    }
}