#pragma once

#include <windows.h>
#include <Structs.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define DLL_QUERY_HMODULE 6

/*----------------------[ Kernel32 ]----------------------*/

typedef LPVOID (WINAPI* fnVirtualAlloc)(
  _In_opt_ LPVOID lpAddress,
  _In_     SIZE_T dwSize,
  _In_     DWORD  flAllocationType,
  _In_     DWORD  flProtect
);

typedef HMODULE (WINAPI* fnLoadLibraryA)(
    LPCSTR lpLibFileName
);

typedef BOOL (WINAPI* fnVirtualProtect)(
  _In_  LPVOID lpAddress,
  _In_  SIZE_T dwSize,
  _In_  DWORD  flNewProtect,
  _Out_ PDWORD lpflOldProtect
);

typedef NTSYSAPI BOOLEAN (WINAPI* fnRtlAddFunctionTable)(
    _In_ PRUNTIME_FUNCTION FunctionTable,
    _In_ DWORD             EntryCount,
    _In_ DWORD64           BaseAddress
);

/*----------------------[ Ntdll ]----------------------*/

typedef NTSYSCALLAPI NTSTATUS (NTAPI* fnNtFlushInstructionCache)(
    _In_     HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_     SIZE_T Length
);

typedef NTSTATUS (NTAPI* fnLdrLoadDll)(
  _In_opt_  PWCHAR            PathToFile,
  _In_opt_  ULONG             Flags,
  _In_      PUNICODE_STRING   ModuleFileName,
  _Out_     PHANDLE           ModuleHandle 
);
typedef NTSTATUS (NTAPI* fnNtProtectVirtualMemory)(
  _In_    HANDLE           ProcessHandle,
  _Inout_ PVOID            *BaseAddress,
  _Inout_ PULONG           NumberOfBytesToProtect,
  _In_    ULONG            NewAccessProtection,
 _Out_    PULONG           OldAccessProtection 
);

typedef NTSTATUS (NTAPI* fnNtAllocateVirtualMemory)(
  _In_    HANDLE    ProcessHandle,
  _Inout_ PVOID     *BaseAddress,
  _In_    ULONG_PTR ZeroBits,
  _Inout_ PSIZE_T   RegionSize,
  _In_    ULONG     AllocationType,
  _In_    ULONG     Protect
);

/*----------------------[ DllMain ]----------------------*/

typedef BOOL(WINAPI* fnDllMain)(HINSTANCE, DWORD, LPVOID);

/*----------------------[ Dynamic Call ]----------------------*/

PVOID LdrModuleAddr( _In_ UINT32 ModuleHash);
PVOID LdrFuncAddr( _In_ PVOID BaseModule, _In_ UINT32 FuncHash);
