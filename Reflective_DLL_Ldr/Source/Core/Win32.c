#include <windows.h>
#include <Common.h>
#include <Structs.h>
#include <Core/Win32.h>

UINT32 CRC32B(LPCSTR cString) {

	UINT32      uMask	= 0x00,
				uHash	= 0xFFFFFFFF;
	INT         i		= 0x00;

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

PVOID LdrModuleAddr( _In_ UINT32 ModuleHash){

    PTEB                  pTeb  = NtCurrentTeb();
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

    Head  = &pTeb->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = C_PTR( Entry );
        if ( CRC32B(Data->BaseDllName.Buffer) == ModuleHash ){
            return C_PTR(Data->DllBase);
        }
    }

    return NULL;
}

PVOID LdrFuncAddr( _In_ PVOID BaseModule, _In_ UINT32 FuncHash ) {

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
        
        if ( CRC32B(pFuncName) == FuncHash ) {
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

/*
PVOID LdrLib( _In_ PINSTANCE pInstance, LPSTR ModuleName ){

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

    if ( NT_SUCCESS( pLdrLoadDll( NULL, 0, &UnicodeString, &Module ) ) )
        return Module;
    else
        return NULL;

}
*/

