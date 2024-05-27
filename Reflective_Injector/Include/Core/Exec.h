#include <windows.h>
#include <Core/Win32.h>

BOOL InjectRDI( _In_ HANDLE hProcess, _In_ HANDLE hThread, _In_ PBYTE pRDI, _In_ DWORD szRDI );