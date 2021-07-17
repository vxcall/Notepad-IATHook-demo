#pragma once
#include <iostream>
#include <Windows.h>
#include <string>
#include <vector>

class Scanner
{
private:
    std::vector<std::string> scanedDllName{};
    std::vector<HMODULE> moduleHandles{};
    const char *targetFunc;
    auto IsScaned(std::string &candidate) -> bool;
    auto ReleaseModuleHandles() -> void;

public:
    Scanner(const char *targetFunc)
        : targetFunc(targetFunc)
    {
    }
    ~Scanner();
    void **targetIATEntry = nullptr;
    auto FindTargetIATEntry(const char *moduleName) -> void;
};
