#pragma once

#include <windows.h>
#include <Core/Win32.h>

BOOL CreateFork( _In_ PWSTR SpawnTo, _In_opt_ PWSTR LegitArgs, _In_opt_ PWSTR FakeArgs, _In_opt_ DWORD *PPid, _Out_ DWORD Pid, _Out_ HANDLE *hProcess, _Out_ HANDLE *hThread );

//BOOL NtCreateUserProcessMinimalPoC( PINSTANCE pInstance, IN PWSTR	szTargetProcess, IN	PWSTR	szTargetProcessParameters,	IN	PWSTR	szTargetProcessPath,	OUT PHANDLE hProcess,	OUT PHANDLE hThread );