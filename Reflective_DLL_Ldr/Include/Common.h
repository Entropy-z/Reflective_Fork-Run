#pragma once

#include <Windows.h>
#include <Structs.h>

#define NtCurrentProcess() ((HANDLE)-1) 
#define NtCurrentThread()  ((HANDLE)-2) 

extern PVOID RDIcaller();
extern PVOID EggHunter();
#define DLLEXPORT extern __declspec(dllexport)

/*----------------------[ Memory ]----------------------*/

PVOID MemCopy( _Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length);
VOID  ZeroMemoryEx( _Inout_ PVOID Destination, _In_ SIZE_T Size);
PVOID MemSet(void* Destination, int Value, size_t Size);

/*----------------------[ Strings ]----------------------*/

int    StringCompareA( _In_ LPCSTR String1, _In_ LPCSTR String2);
SIZE_T StringLengthA( _In_ LPCSTR String );
SIZE_T StringLengthW(_In_ LPCWSTR String);
int    wCharCompare( _In_ const WCHAR *s1, _In_ const WCHAR *s2 );
SIZE_T CharStringToWCharString(_Inout_ PWCHAR Destination, _In_ PCHAR Source, SIZE_T _In_ MaximumAllowed);
void   InitUnicodeString( _Out_ PUNICODE_STRING UsStruct, _In_opt_ PCWSTR Buffer);

/*----------------------[ Defines ]----------------------*/

#define C_PTR( x )   ( ( LPVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )

#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

/*----------------------[ Hashes ]----------------------*/

#define NtFlushInstructionCache_H 0x85BF2F9C
#define NtAllocateVirtualMemory_H 0xE0762FEB
#define RtlAddFunctionTable_H     0x4C3CB59B
#define LoadLibraryA_H            0x3FC1BD8D
#define VirtualAlloc_H            0x09CE0D4A
#define VirtualProtect_H          0x10066F2F
#define ntdlldll_H                0x7808A3D2
#define KERNEL32DLL_H             0x330C7795