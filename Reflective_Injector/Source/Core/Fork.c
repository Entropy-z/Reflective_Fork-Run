#include <windows.h>
#include <Common.h>
#include <Core/Fork.h>

BOOL CreateFork( _In_ PWSTR SpawnTo, _In_opt_ PWSTR LegitArgs, _In_opt_ PWSTR FakeArgs, _In_opt_ DWORD *PPid, _Out_ DWORD Pid, _Out_ HANDLE *hProcess, _Out_ HANDLE *hThread ){
    
    PVOID           pHeap         = Instance->pTeb->ProcessEnvironmentBlock->ProcessHeap;
    NTSTATUS        Status        = 0x00;
    PWSTR           Path          = L"C:\\Windows\\System32";
    UNICODE_STRING  usNtImagePath = { 0 },
                    usCmdLine     = { 0 },
                    usCurDir      = { 0 };
                    
    PS_CREATE_INFO	psCreateInfo = {
					.Size  = sizeof(PS_CREATE_INFO),
					.State = PsCreateInitialState
	};

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = { 0 };
    PPS_ATTRIBUTE_LIST           pAttributeList    = (PPS_ATTRIBUTE_LIST)Instance->Api.pRtlAllocateHeap( pHeap, HEAP_ZERO_MEMORY, sizeof( PS_ATTRIBUTE_LIST ) );

    InitUnicodeString( &usNtImagePath, SpawnTo );
    InitUnicodeString( &usCmdLine, LegitArgs );
    InitUnicodeString( &usCurDir, Path );

	Status = Instance->Api.pRtlCreateProcessParametersEx( &ProcessParameters, &usNtImagePath, NULL, &usCurDir, &usCmdLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if ( Status != 0 ) {
		goto _End;
	}

   	pAttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);

	pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size		= usNtImagePath.Length;
	pAttributeList->Attributes[0].Value		= (ULONG_PTR)usNtImagePath.Buffer;

    Status = Instance->Api.pNtCreateUserProcess( hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, ProcessParameters, &psCreateInfo, pAttributeList );
    if ( Status != 0 ){
        goto _End;
    }
  
_End:
	//Instance->Api.pRtlFreeHeap( pHeap, 0, pAttributeList );
	if (*hProcess == NULL || *hThread == NULL)
		return FALSE;
	else
		return TRUE;
}