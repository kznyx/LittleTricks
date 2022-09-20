#include <Windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "Shlwapi.lib")

#define NEW_STREAM_NAME L":wtfbbq"
#define DEBUG_LOG(msg) wprintf(L"[LOG] - %s\n", msg)

HANDLE OpenFile(PWCHAR pwPath)
{
	return CreateFileW(pwPath, GENERIC_READ | DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

BOOL SetFileRename(HANDLE hHandle)
{
	PFILE_RENAME_INFO pFileRenameInfo = (PFILE_RENAME_INFO)new char[0x100];
	RtlSecureZeroMemory(pFileRenameInfo, 0x100);

	// set our FileNameLength and FileName to DS_STREAM_RENAME
	LPWSTR lpwStream = (LPWSTR)NEW_STREAM_NAME;
	//fRename.FileNameLength = sizeof(lpwStream);
	pFileRenameInfo->FileNameLength = lstrlenW(lpwStream) * 2;
	//pFileRenameInfo.FileName = lpwStream;
	RtlCopyMemory(pFileRenameInfo->FileName, lpwStream, pFileRenameInfo->FileNameLength);

	return SetFileInformationByHandle(hHandle, FileRenameInfo, pFileRenameInfo, 0x100);
}

BOOL SetFileDelete(HANDLE hHandle)
{
	// set FILE_DISPOSITION_INFO::DeleteFile to TRUE
	FILE_DISPOSITION_INFO fDelete;
	RtlSecureZeroMemory(&fDelete, sizeof(fDelete));

	fDelete.DeleteFile = TRUE;

	return SetFileInformationByHandle(hHandle, FileDispositionInfo, &fDelete, sizeof(fDelete));
}

int wmain(int argc, wchar_t** argv)
{
	WCHAR wcPath[MAX_PATH];
	RtlSecureZeroMemory(wcPath, sizeof(wcPath));

	// get the path to the current running process ctx
	if (GetModuleFileNameW(NULL, wcPath, MAX_PATH) == 0)
	{
		DEBUG_LOG(L"failed to get the current module handle");
		return 0;
	}

	HANDLE hFile = OpenFile(wcPath);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		DEBUG_LOG(L"failed to acquire handle to current running process");
		return 0;
	}

	// rename the associated HANDLE's file name
	DEBUG_LOG(L"attempting to rename file name");
	if (!SetFileRename(hFile))
	{
		DEBUG_LOG(L"failed to rename to stream");
		return 0;
	}

	DEBUG_LOG(L"successfully renamed file primary :$DATA ADS to specified stream, closing initial handle");
	CloseHandle(hFile);

	// open another handle, trigger deletion on close
	hFile = OpenFile(wcPath);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		DEBUG_LOG(L"failed to reopen current module");
		return 0;
	}

	if (!SetFileDelete(hFile))
	{
		DEBUG_LOG(L"failed to set delete deposition");
		return 0;
	}

	// trigger the deletion deposition on hCurrent
	DEBUG_LOG(L"closing handle to trigger deletion deposition");
	CloseHandle(hFile);

	// verify we've been deleted
	if (PathFileExistsW(wcPath))
	{
		DEBUG_LOG(L"failed to delete copy, file still exists");
		return 0;
	}

	DEBUG_LOG(L"successfully deleted self from disk");
	return 0;
}