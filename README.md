# Notepad-IATHook-demo

This is a demo of Import address table hooking tested with Notepad.

I'm still working on it so it doesn't work as it finally should do.

So basically this program (is being) designed to hook the function called `CreateFileW()` imported from `KERNEL32.dll` or equivalent to inject and perform my own code which doesn't relate to
the original functionallity.

# Definition of CreateFileW

Quoted from: [Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)

```cpp
HANDLE CreateFileW(
  LPCWSTR               lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);
```

# What makes me do this?

Because why not? Hooking is beautiful.