# Notepad-IATHook-demo

This is a demo of Import address table hooking tested with Notepad.

I'm still working on it so it doesn't work as it finally should do.

So basically this program (is being) designed to hook the function called `NtCreateFile()` imported from `ntdll.dll` to inject and perform my own code which doesn't relate to
the original functionallity.

# Definition of NtCreateFile

Quoted from: [Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)

```cpp
__kernel_entry NTSYSCALLAPI NTSTATUS NtCreateFile(
  PHANDLE            FileHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK   IoStatusBlock,
  PLARGE_INTEGER     AllocationSize,
  ULONG              FileAttributes,
  ULONG              ShareAccess,
  ULONG              CreateDisposition,
  ULONG              CreateOptions,
  PVOID              EaBuffer,
  ULONG              EaLength
);
```

# What makes me do this?

Because why not? Hooking is beautiful.