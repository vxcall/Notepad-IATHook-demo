#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

namespace Process
{
    auto GetProcessHandle(const char *processName) -> HANDLE;
}