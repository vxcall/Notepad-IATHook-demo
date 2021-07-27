![header](https://user-images.githubusercontent.com/33578715/127169129-80aa53f8-3f54-4549-80b5-e2c19bfaa790.PNG)
# Notepad-IATHook-demo

This is a demo of Import address table hooking tested with Notepad.

So basically this program (is being) designed to hook the function called `CreateFileW()` imported from `KERNEL32.dll` or an equivalent to inject and perform my own code which doesn't relate to the original functionallity.

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

# How to run this

Build this project.
Open notepad.exe and inject the generated dll and click "save as...".
And BOOOM! A messagebox saying "CreateFileW function has been hooked" will pop up!

Needless to say anything other than messagebox would work if you code so.


# What makes me do this?

Because why not? Hooking is beautiful.
