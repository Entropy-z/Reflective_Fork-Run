#pragma once

#include <Windows.h>
#include <Core/Win32.h>
#include <Structs.h>

#define ERROR_BUF_SIZE					(MAX_PATH * 2)

#ifdef DEBUG

#define DEBUG( STR, ... )                                                                           \
    if (1) {                                                                                        \
        LPSTR cBuffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ERROR_BUF_SIZE);       \
        if (cBuffer){                                                                               \
            int iLength = wsprintfA(cBuffer, STR, __VA_ARGS__);                                     \
            WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), cBuffer, iLength, NULL, NULL);           \
            HeapFree(GetProcessHeap(), 0x00, cBuffer);                                              \
        }                                                                                           \
    }  

#endif

/*----------------------[ Memory ]----------------------*/

PVOID MemCopy( _Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length);
void  ZeroMemoryEx( _Inout_ PVOID Destination, _In_ SIZE_T Size);
PVOID MemSet(void* Destination, int Value, size_t Size);

/*----------------------[ Strings ]----------------------*/

int    StringCompareA( _In_ LPCSTR String1, _In_ LPCSTR String2 );
SIZE_T StringLengthA( _In_ LPCSTR String );
SIZE_T StringLengthW(_In_ LPCWSTR String);
int    wCharCompare( _In_ const WCHAR *s1, _In_ const WCHAR *s2 );
SIZE_T CharStringToWCharString(_Inout_ PWCHAR Destination, _In_ PCHAR Source, SIZE_T _In_ MaximumAllowed);
void   InitUnicodeString( _Out_ PUNICODE_STRING UsStruct, _In_opt_ PCWSTR Buffer);

