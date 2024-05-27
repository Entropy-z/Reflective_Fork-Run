#include <windows.h>
#include <Core/Win32.h>
#include <Common.h>
#include <Structs.h>

BOOL ResolveIat( _In_ PIMAGE_DATA_DIRECTORY pEntryImport, _In_ DWORD64 NewImgAddr) {

    fnLoadLibraryA pLoadLibraryA = LdrFuncAddr(LdrModuleAddr(KERNEL32DLL_H), LoadLibraryA_H);

	PIMAGE_IMPORT_DESCRIPTOR ImportDesc = NewImgAddr + pEntryImport->VirtualAddress;

	for (SIZE_T i = 0; ImportDesc->Name; ImportDesc++) {

		PIMAGE_THUNK_DATA IAT = NewImgAddr + ImportDesc->FirstThunk;
		PIMAGE_THUNK_DATA ILT = NewImgAddr + ImportDesc->OriginalFirstThunk;

		PCHAR DllName = NewImgAddr + ImportDesc->Name;

		HMODULE hDll = LdrModuleAddr( CRC32B(DllName) );
		if (!hDll) {
			hDll = LdrLib( DllName );
			if (!hDll) {
				return FALSE;
			}
		}

		for (; ILT->u1.Function; IAT++, ILT++) {

			if (IMAGE_SNAP_BY_ORDINAL(ILT->u1.Ordinal)) {

				LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(ILT->u1.Ordinal);
				IAT->u1.Function = (DWORD_PTR)LdrFuncAddr(hDll, CRC32B(functionOrdinal));

				if ( !IAT->u1.Function ){
					return FALSE;
				}

			}
			else {

				IMAGE_IMPORT_BY_NAME* Hint = NewImgAddr + ILT->u1.AddressOfData;
				IAT->u1.Function = LdrFuncAddr(hDll, CRC32B(Hint->Name));

				if ( !IAT->u1.Function ){
					return FALSE;
				}

			}
		}
	}
	
	return TRUE;

}

BOOL FixReloc( _In_ PIMAGE_DATA_DIRECTORY pEntryReloc, _In_ ULONG_PTR NewImgAddr, _In_ ULONG_PTR uDeltaOffset) {

    DWORD_PTR RelocTable = pEntryReloc->VirtualAddress + (DWORD_PTR)NewImgAddr;
    DWORD RelocProcessed = 0;

    while (RelocProcessed < pEntryReloc->Size) {
        PIMAGE_RELOCATION_BLOCK RelocBlock = (PIMAGE_RELOCATION_BLOCK)(RelocTable + RelocProcessed);
        RelocProcessed += sizeof(IMAGE_RELOCATION_BLOCK);
        DWORD RelocCount = (RelocBlock->BlockSize - sizeof(IMAGE_RELOCATION_BLOCK)) / sizeof(IMAGE_RELOCATION_ENTRY);
        PIMAGE_RELOCATION_ENTRY RelocEntry = (PIMAGE_RELOCATION_ENTRY)(RelocTable + RelocProcessed);

        for (DWORD i = 0; i < RelocCount; i++) {
            RelocProcessed += sizeof(IMAGE_RELOCATION_ENTRY);
            if (RelocEntry[i].Type == 0) {
                continue;
            }

            DWORD_PTR relocationRVA = RelocBlock->PageAddress + RelocEntry[i].Offset;
            DWORD_PTR* addressToPatch = (DWORD_PTR*)((DWORD_PTR)NewImgAddr + relocationRVA);
            *addressToPatch += uDeltaOffset;
        }
    }

    return TRUE;
}

DLLEXPORT BOOL ReflectiveLdr( LPVOID lpParameter ) {

    LPVOID DllAddr  = NULL;
    DWORD  dwOffset = 0x00;

    fnVirtualAlloc            pVirtualAlloc            = LdrFuncAddr(LdrModuleAddr(KERNEL32DLL_H), VirtualAlloc_H);
    fnLoadLibraryA            pLoadLibraryA            = LdrFuncAddr(LdrModuleAddr(KERNEL32DLL_H), LoadLibraryA_H);
    fnVirtualProtect          pVirtualProtect          = LdrFuncAddr(LdrModuleAddr(KERNEL32DLL_H), VirtualProtect_H);
    fnNtFlushInstructionCache pNtFlushInstructionCache = LdrFuncAddr(LdrModuleAddr(ntdlldll_H), NtFlushInstructionCache_H);

	ULONG_PTR LibAddr = RDIcaller();

	PIMAGE_NT_HEADERS		pImgNtHdrs	 = { 0 };
	PIMAGE_SECTION_HEADER   pImgSectHdr  = { 0 };
    PIMAGE_DATA_DIRECTORY   pEntryReloc  = { 0 };
    PIMAGE_DATA_DIRECTORY   pEntryImport = { 0 };

	pImgNtHdrs   = (LibAddr + ((PIMAGE_DOS_HEADER)LibAddr)->e_lfanew);
    pImgSectHdr  = IMAGE_FIRST_SECTION(pImgNtHdrs);
    pEntryImport = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    pEntryReloc  = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    DllAddr = pVirtualAlloc( NULL, pImgNtHdrs->OptionalHeader.SizeOfImage, 0x3000, 0x4);

    for ( int i = 0 ; i < pImgNtHdrs->FileHeader.NumberOfSections; i++ ){
        MemCopy(
            C_PTR(DllAddr + pImgSectHdr[i].VirtualAddress),
            C_PTR(LibAddr + pImgSectHdr[i].PointerToRawData),
            pImgSectHdr[i].SizeOfRawData
        );
    }

    dwOffset = DEREF_64(DllAddr) - pImgNtHdrs->OptionalHeader.ImageBase;

	ResolveIat( pEntryImport, DllAddr );
	FixReloc  ( pEntryReloc, U_PTR(DllAddr), U_PTR(dwOffset) );

    for ( int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++ ) {

		DWORD	dwProtection	= 0x00;
		DWORD	dwOldProtection	= 0x00;

		if ( !pImgSectHdr[i].SizeOfRawData || !pImgSectHdr[i].VirtualAddress )
			continue;

		if ( pImgSectHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE )
			dwProtection = PAGE_WRITECOPY;

		if ( pImgSectHdr[i].Characteristics & IMAGE_SCN_MEM_READ )
			dwProtection = PAGE_READONLY;

		if ( ( pImgSectHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && (pImgSectHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;

		if (pImgSectHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if ((pImgSectHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pImgSectHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READ;

		if ((pImgSectHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSectHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;

		if ( !pVirtualProtect( (PVOID)(DllAddr + pImgSectHdr[i].VirtualAddress), pImgSectHdr[i].SizeOfRawData, dwProtection, &dwOldProtection ) ) {
			return;
		}
	}

	pNtFlushInstructionCache( (HANDLE)-1, NULL, 0 );

	ULONG_PTR EntryPoint = ( U_PTR(DllAddr) + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint );

	((fnDllMain)EntryPoint)( (HINSTANCE)DllAddr, DLL_PROCESS_ATTACH, lpParameter );

	return EntryPoint;

}

HINSTANCE hAppInstance = NULL;

//===============================================================================================//

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
   	CHAR hell[] = { 'R', 'e', 'f', 'l', 'e', 'c', 't', 'e', 'd', ' ', 'B', 'y', ' ', 'O', 'b', 'l', 'i', 'v', 'i', 'o', 'n', 0 };
    PCHAR aaaa = "Test";

    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			MessageBoxA( NULL, hell, aaaa, MB_OK );
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}