#include <iostream>
#include <windows.h>
#include <winternl.h>

#pragma comment(lib,"ntdll.lib")


#define STATUS_SUCCESS				((NTSTATUS)0x00000000L) // ntsubauth
// #define NT_SUCCESS(Status) ((NTSTATUS)(Status) == STATUS_SUCCESS)

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtCreateTransaction(
  OUT          PHANDLE            TransactionHandle,
  IN           ACCESS_MASK        DesiredAccess,
  IN OPTIONAL  POBJECT_ATTRIBUTES ObjectAttributes,
  IN OPTIONAL  LPGUID             Uow,
  IN OPTIONAL  HANDLE             TmHandle,
  IN OPTIONAL  ULONG              CreateOptions,
  IN OPTIONAL  ULONG              IsolationLevel,
  IN OPTIONAL  ULONG              IsolationFlags,
  IN OPTIONAL  PLARGE_INTEGER     Timeout,
  IN OPTIONAL  PUNICODE_STRING    Description
);

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtRollbackTransaction(
  IN HANDLE  TransactionHandle,
  IN BOOLEAN Wait
);

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtCreateSection(
  OUT         PHANDLE            SectionHandle,
  IN          ACCESS_MASK        DesiredAccess,
  IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
  IN OPTIONAL PLARGE_INTEGER     MaximumSize,
  IN          ULONG              SectionPageProtection,
  IN          ULONG              AllocationAttributes,
  IN OPTIONAL HANDLE             FileHandle
);

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtRollbackTransaction(
  IN HANDLE  TransactionHandle,
  IN BOOLEAN Wait
);

// EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtClose(
//   IN HANDLE Handle
// );

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtCreateProcessEx(
    OUT         PHANDLE             ProcessHandle,
    IN          ACCESS_MASK         DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES  ObjectAttributes,
    IN          HANDLE 	            ParentProcess,
    IN          ULONG 	            Flags,
    IN OPTIONAL HANDLE              SectionHandle,
    IN          HANDLE              DebugPort,
    IN OPTIONAL HANDLE              ExceptionPort,
    IN OPTIONAL BOOLEAN             InJob
);

#define PS_INHERIT_HANDLES  4

// EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationProcess(
//   IN            HANDLE           ProcessHandle,
//   IN            PROCESSINFOCLASS ProcessInformationClass,
//   OUT           PVOID            ProcessInformation,
//   IN            ULONG            ProcessInformationLength,
//   OUT OPTIONAL  PULONG           ReturnLength
// );

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtReadVirtualMemory(
	IN		       HANDLE  ProcessHandle,
	IN OPTIONAL  PVOID   BaseAddress,
	OUT		       PVOID   Buffer,
	IN		       SIZE_T  BufferSize,
	OUT OPTIONAL PSIZE_T NumberOfBytesRead
);

EXTERN_C NTSYSCALLAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
  IN PVOID Base
);

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI RtlCreateProcessParametersEx(
  OUT         PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
  IN          PUNICODE_STRING               ImagePathName,
  IN OPTIONAL PUNICODE_STRING               DllPath,
  IN OPTIONAL PUNICODE_STRING               CurrentDirectory,
  IN OPTIONAL PUNICODE_STRING               CommandLine,
  IN OPTIONAL PVOID                         Environment,
  IN OPTIONAL PUNICODE_STRING               WindowTitle,
  IN OPTIONAL PUNICODE_STRING               DesktopInfo,
  IN OPTIONAL PUNICODE_STRING               ShellInfo,
  IN OPTIONAL PUNICODE_STRING               RuntimeData,
  IN          ULONG                         Flags
);

#define RTL_USER_PROC_PARAMS_NORMALIZED     0x00000001

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtAllocateVirtualMemory(
  IN       HANDLE    ProcessHandle,
  IN OUT   PVOID     *BaseAddress,
  IN       ULONG_PTR ZeroBits,
  IN OUT   PSIZE_T   RegionSize,
  IN       ULONG     AllocationType,
  IN       ULONG     Protect
);


// typedef struct _PEB_LDR_DATA {
// 	BYTE Reserved1[8];
// 	PVOID Reserved2[3];
// 	LIST_ENTRY InMemoryOrderModuleList;
// } PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT                  Flags;
	USHORT                  Length;
	ULONG                   TimeStamp;
	UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;
typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, * PCURDIR;

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _RTL_USER_PROCESS_PARAMETERS_
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
	PVOID PackageDependencyData; //8+
	ULONG ProcessGroupId;
	// ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS_, * PRTL_USER_PROCESS_PARAMETERS_;

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtWriteVirtualMemory(
	IN            HANDLE  ProcessHandle,
	IN OPTIONAL   PVOID   BaseAddress,
	IN            VOID*   Buffer,
	IN            SIZE_T  BufferSize,
	OUT OPTIONAL  PSIZE_T NumberOfBytesWritten
);

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtCreateThreadEx(
	OUT PHANDLE                hThread,
	IN  ACCESS_MASK            DesiredAccess,
	IN  LPVOID                 ObjectAttributes,
	IN  HANDLE                 ProcessHandle,
	IN  LPTHREAD_START_ROUTINE lpStartAddress,
	IN  LPVOID                 lpParameter,
	IN  BOOL                   CreateSuspended,
	IN  DWORD                  StackZeroBits,
	IN  DWORD                  SizeOfStackCommit,
	IN  DWORD                  SizeOfStackReserve,
	OUT LPVOID                 lpBytesBuffer);

typedef struct _PEB_FREE_BLOCK {
	_PEB_FREE_BLOCK* Next;
	ULONG                   Size;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;


typedef void (*PPEBLOCKROUTINE)(
	PVOID PebLock
	);


typedef struct _PEB_ {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PPEBLOCKROUTINE         FastPebLockRoutine;
	PPEBLOCKROUTINE         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PPEB_FREE_BLOCK         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB_, * PPEB_;

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;


EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtMapViewOfSection(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Protect
);