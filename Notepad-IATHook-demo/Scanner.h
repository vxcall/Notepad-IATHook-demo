#pragma once
#include <iostream>
#include <Windows.h>
#include <string>
#include <vector>

class Scanner
{
private:
	const char* targetFunc;
	auto IsScaned(std::string& candidate) -> bool;
	std::vector<std::string> scanedDllName{};
public:
	Scanner(const char* targetFunc)
		: targetFunc(targetFunc)
	{
	}
	~Scanner() {}
	void** targetIATEntry = nullptr;
	auto FindTargetIATEntry(const char* moduleName) -> void;
};
