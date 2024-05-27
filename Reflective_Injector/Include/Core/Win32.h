#pragma once

#include <windows.h>
#include <Structs.h>
#include <winhttp.h>

#define C_PTR( x )   ( ( LPVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	PVOID				      ApcContext,
	PIO_STATUS_BLOCK	IoStatusBlock,
	ULONG				      Reserved
);

/*----------------------[ WinHttp ]----------------------*/

typedef HINTERNET(WINAPI *fnWinHttpOpen)(
  LPCWSTR pwszUserAgent,
  DWORD   dwAccessType,
  LPCWSTR pwszProxyName,
  LPCWSTR pwszProxyBypass,
  DWORD   dwFlags
);

typedef HINTERNET(WINAPI *fnWinHttpConnect)(
  HINTERNET     hSession,
  LPCWSTR       pswzServerName,
  INTERNET_PORT nServerPort,
  DWORD         dwReserved
);

typedef HINTERNET(WINAPI *fnWinHttpOpenRequest)(
  HINTERNET hConnect,
  LPCWSTR   pwszVerb,
  LPCWSTR   pwszObjectName,
  LPCWSTR   pwszVersion,
  LPCWSTR   pwszReferrer,
  LPCWSTR   *ppwszAcceptTypes,
  DWORD     dwFlags
);

typedef BOOL(WINAPI *fnWinHttpSendRequest)(
  HINTERNET hRequest,
  LPCWSTR   pwszHeaders,
  DWORD     dwHeadersLength,
  LPVOID    lpOptional,
  DWORD     dwOptionalLength,
  DWORD     dwTotalLength,
  DWORD_PTR dwContext
);

typedef BOOL(WINAPI *fnWinHttpReceiveResponse)(
  HINTERNET     hRequest,
  LPVOID        lpReserved
);

typedef BOOL(WINAPI *fnWinHttpReadData)(
  HINTERNET hRequest,
  LPVOID    lpBuffer,
  DWORD     dwNumberOfBytesToRead,
  LPDWORD   lpdwNumberOfBytesRead
);

typedef BOOL (WINAPI* fnWinHttpQueryHeaders)(
  _In_         HINTERNET hRequest,
  _In_         DWORD     dwInfoLevel,
  _In_opt_     LPCWSTR   pwszName,
  _Out_        LPVOID    lpBuffer,
  _Inout_      LPDWORD   lpdwBufferLength,
  _Inout_      LPDWORD   lpdwIndex
);


typedef BOOL(WINAPI *fnWinHttpCloseHandle)(
  HINTERNET hInternet
);

/*----------------------[ Ntdll ]----------------------*/

typedef NTSTATUS (NTAPI* fnRtlCreateProcessParametersEx)(
    _Out_ 	 PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    _In_ 		 PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,         // set to NULL
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,              // set to NULL
    _In_opt_ PUNICODE_STRING WindowTitle,    // set to NULL
    _In_opt_ PUNICODE_STRING DesktopInfo,    // set to NULL
    _In_opt_ PUNICODE_STRING ShellInfo,      // set to NULL
    _In_opt_ PUNICODE_STRING RuntimeData,    // set to NULL
    _In_     ULONG Flags 
);

typedef NTSTATUS (NTAPI* fnLdrLoadDll)(
  _In_opt_  PWCHAR            PathToFile,
  _In_opt_  ULONG             Flags,
  _In_      PUNICODE_STRING   ModuleFileName,
  _Out_     PHANDLE           ModuleHandle 
);

typedef PVOID (NTAPI *fnRtlAllocateHeap)(
  _In_       PVOID  HeapHandle,
  _In_opt_   ULONG  Flags,
  _In_       SIZE_T Size
);

typedef PVOID (NTAPI *fnRtlReAllocateHeap)(
  _In_   PVOID   HeapHandle,
  _In_   ULONG   Flags,
  _In_   PVOID   MemoryPointer,
  _In_   ULONG   Size
);

typedef BOOL (NTAPI* fnRtlFreeHeap)(
  _In_     PVOID    HeapHandle,
  _In_opt_ ULONG    Flags,
  _In_     PVOID    MemoryPointer
);

typedef NTSTATUS (NTAPI* fnNtQueueApcThread)(
    _In_     HANDLE               ThreadHandle,
    _In_     PIO_APC_ROUTINE      ApcRoutine,
    _In_opt_ PVOID                ApcRoutineContext,
    _In_opt_ PIO_STATUS_BLOCK     ApcStatusBlock,
    _In_opt_ ULONG                ApcReserved 
);

typedef NTSTATUS (NTAPI* fnNtCreateThreadEx)(
  _Out_ PHANDLE     hThread,
  _In_  ACCESS_MASK DesiredAccess,
  _In_  PVOID       ObjectAttributes,
  _In_  HANDLE      ProcessHandle,
  _In_  PVOID       lpStartAddress,
  _In_  PVOID       lpParameter,
  _In_  ULONG       Flags,
  _In_  SIZE_T      StackZeroBits,
  _In_  SIZE_T      SizeOfStackCommit,
  _In_  SIZE_T      SizeOfStackReserve,
  _Out_ PVOID       lpBytesBuffer
);

typedef NTSTATUS (NTAPI* fnNtCreateUserProcess)(
    _Out_     PHANDLE             ProcessHandle,
    _Out_     PHANDLE             ThreadHandle,
    _In_      ACCESS_MASK         ProcessDesiredAccess,
    _In_      ACCESS_MASK         ThreadDesiredAccess,
    _In_opt_  POBJECT_ATTRIBUTES  ProcessObjectAttributes,
    _In_opt_  POBJECT_ATTRIBUTES  ThreadObjectAttributes,
    _In_      ULONG               ProcessFlags,           // PROCESS_CREATE_FLAGS_*
    _In_      ULONG               ThreadFlags,            // THREAD_CREATE_FLAGS_*
    _In_opt_  PVOID               ProcessParameters,      // PRTL_USER_PROCESS_PARAMETERS
    _Inout_   PPS_CREATE_INFO     CreateInfo,
    _In_opt_  PPS_ATTRIBUTE_LIST  AttributeList
);

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(

    HANDLE				ProcessHandle,
    PVOID*        BaseAddress,
    ULONG_PTR			ZeroBits,
    PSIZE_T				RegionSize,
    ULONG					AllocationType,
    ULONG					Protect
);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(

    HANDLE				ProcessHandle,
    PVOID*        BaseAddress,
    PSIZE_T				NumberOfBytesToProtect,
    ULONG					NewAccessProtection,
    PULONG				OldAccessProtection
);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(

    HANDLE					ProcessHandle,
    PVOID						BaseAddress,
    PVOID						Buffer,
    ULONG						NumberOfBytesToWrite,
    PULONG					NumberOfBytesWritten
);

/*----------------------[ DllMain ]----------------------*/

typedef BOOL(WINAPI* fnDllMain)(HINSTANCE, DWORD, LPVOID);

/*----------------------[ Instance ]----------------------*/

typedef struct _INSTANCE {
  
  struct {

    fnNtAllocateVirtualMemory        pNtAllocateVirtualMemory; 
    fnNtProtectVirtualMemory         pNtProtectVirtualMemory;
    fnNtWriteVirtualMemory           pNtWriteVirtualMemory;
    fnNtCreateThreadEx               pNtCreateThreadEx;
    fnNtQueueApcThread               pNtQueueApcThread;

    fnNtCreateUserProcess            pNtCreateUserProcess;
    fnRtlCreateProcessParametersEx   pRtlCreateProcessParametersEx;

    fnLdrLoadDll                     pLdrLoadDll;

    fnRtlAllocateHeap                pRtlAllocateHeap;
    fnRtlReAllocateHeap              pRtlReAllocateHeap;
    fnRtlFreeHeap                    pRtlFreeHeap;

    fnWinHttpOpen                    pWinHttpOpen;
    fnWinHttpConnect                 pWinHttpConnect;
    fnWinHttpOpenRequest             pWinHttpOpenRequest;
    fnWinHttpSendRequest             pWinHttpSendRequest;
    fnWinHttpReceiveResponse         pWinHttpReceiveResponse;
    fnWinHttpReadData                pWinHttpReadData;
    fnWinHttpQueryHeaders            pWinHttpQueryHeaders;
    fnWinHttpCloseHandle             pWinHttpCloseHandle;

  } Api;

  struct {

    PVOID Ntdll;
    PVOID WinHttp;

  } Module;

  PTEB pTeb;

} INSTANCE, *PINSTANCE; 

/*----------------------[ PE INFO ]----------------------*/

typedef struct _PE_INFO{

    PBYTE                    pPeBuffer;
    DWORD                    dwPeSize;

    PIMAGE_NT_HEADERS        pImgNtHdrs;
    PIMAGE_SECTION_HEADER    pImgSecHdr;

    PIMAGE_DATA_DIRECTORY    pEntryImportDataDir;
    PIMAGE_DATA_DIRECTORY    pEntryBaseRelocDataDir;
    PIMAGE_DATA_DIRECTORY    pEntryTLSDataDir;
    PIMAGE_DATA_DIRECTORY    pEntryExceptionDataDir;
    PIMAGE_DATA_DIRECTORY    pEntryExportDataDir;
    
} PE_INFO, *PPE_INFO;

/*----------------------[ Dynamic Call ]----------------------*/

PVOID LdrModuleAddr( _In_ LPWSTR ModuleName);
PVOID LdrFuncAddr( _In_ PVOID BaseModule, _In_ PCHAR FuncName);
PVOID LdrLib( PINSTANCE Instance, LPSTR ModuleName );

extern PINSTANCE Instance;

//void InitInstance( _Out_ PINSTANCE pInstance );