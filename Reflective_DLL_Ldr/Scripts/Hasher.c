#include <windows.h>
#include <stdio.h>

UINT32 CRC32B(LPCSTR cString) {
    UINT32 uMask = 0x00,
           uHash = 0xFFFFFFFF;
    INT i = 0x00;

    while (cString[i] != 0) {
        uHash = uHash ^ (UINT32)cString[i];

        for (int ii = 0; ii < 8; ii++) {
            uMask = -1 * (uHash & 1);
            uHash = (uHash >> 1) ^ (0xEDB88320 & uMask);
        }

        i++;
    }

    return ~uHash;
}

int main() {
    PCHAR ListFunc[] = {

        "LdrLoadDll",
        "NtFlushInstructionCache",
        "RtlAddFunctionTable",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",

        "GetProcAddress",
        "LoadLibraryA",
        "VirtualAlloc",
        "VirtualProtect",

    };

    PWCHAR ListModules[] = {
        L"ntdll.dll",
        L"KERNEL32.DLL"
    };

    for (int j = 0; j < sizeof(ListFunc) / sizeof(ListFunc[0]); j++) {
        UINT32 hash = CRC32B(ListFunc[j]);
        printf("#define %s_H 0x%08X\n", ListFunc[j], hash);
    }

    for (int i = 0; i < sizeof(ListModules) / sizeof(ListModules[0]); i++) {
        UINT32 hash = CRC32B(ListModules[i]);
        wprintf(L"#define %ls_H 0x%08X\n", ListModules[i], hash);  
    }

    return 0;
}
