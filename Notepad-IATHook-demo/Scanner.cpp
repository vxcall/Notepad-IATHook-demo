#include "Scanner.h"

auto Scanner::IsScaned(std::string& candidate) -> bool
{
	for (auto& scaned : this->scanedDllName)
	{
		if (candidate == scaned)
		{
			return true;
		}
	}
	this->scanedDllName.push_back(candidate);
	return false;
}

auto Scanner::FindTargetIATEntry(const char* moduleName) -> void
{
	static bool found = false;

	size_t dosBase = reinterpret_cast<size_t>(GetModuleHandle(moduleName));
	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dosBase);
	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(dosBase + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeaders->OptionalHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(dosBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if (!pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	{
		return;
	}

	for (; pImportDescriptor->Characteristics; ++pImportDescriptor)
	{
		char* dllName = reinterpret_cast<char*>(dosBase + pImportDescriptor->Name);

		if (found == true)
		{
			return;
		}
		if (std::string(dllName) != "" && !IsScaned(std::string(dllName)))
		{
			//std::cout << dllName << std::endl;

			DWORD* ILTBase = reinterpret_cast<DWORD*>(dosBase + pImportDescriptor->OriginalFirstThunk); //Import lookup table pointer is somewhere on the memory and OriginalFirstThunk tells you the relative location.

			for (int i = 0; reinterpret_cast<PIMAGE_THUNK_DATA>(ILTBase + i)->u1.AddressOfData; ++i)
			{
				PIMAGE_IMPORT_BY_NAME funcInfo = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(dosBase + *(ILTBase + i));
				//std::cout << funcInfo->Name << std::endl;

				if (!strcmp(funcInfo->Name, this->targetFunc))
				{
					found = true;
					this->targetIATEntry = i + reinterpret_cast<void**>(dosBase + pImportDescriptor->FirstThunk);
					//std::cout << funcInfo->Name << std::endl;
				}
			}
			//FindTargetIATEntry(dllName);
		}
	}
}