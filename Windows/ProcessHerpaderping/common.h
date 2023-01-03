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

typedef struct _PEB_
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    VOID* Mutant;                                                           //0x8
    VOID* ImageBaseAddress;                                                 //0x10
    struct _PEB_LDR_DATA* Ldr;                                              //0x18
    struct _RTL_USER_PROCESS_PARAMETERS_* ProcessParameters;                 //0x20
    VOID* SubSystemData;                                                    //0x28
    VOID* ProcessHeap;                                                      //0x30
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
    union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
    VOID* IFEOKey;                                                          //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob:1;                                           //0x50
            ULONG ProcessInitializing:1;                                    //0x50
            ULONG ProcessUsingVEH:1;                                        //0x50
            ULONG ProcessUsingVCH:1;                                        //0x50
            ULONG ProcessUsingFTH:1;                                        //0x50
            ULONG ProcessPreviouslyThrottled:1;                             //0x50
            ULONG ProcessCurrentlyThrottled:1;                              //0x50
            ULONG ProcessImagesHotPatched:1;                                //0x50
            ULONG ReservedBits0:24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        VOID* KernelCallbackTable;                                          //0x58
        VOID* UserSharedInfoPtr;                                            //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    VOID* ApiSetMap;                                                        //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    VOID* TlsBitmap;                                                        //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    VOID* ReadOnlySharedMemoryBase;                                         //0x88
    VOID* SharedData;                                                       //0x90
    VOID** ReadOnlyStaticServerData;                                        //0x98
    VOID* AnsiCodePageData;                                                 //0xa0
    VOID* OemCodePageData;                                                  //0xa8
    VOID* UnicodeCaseTableData;                                             //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    VOID** ProcessHeaps;                                                    //0xf0
    VOID* GdiSharedHandleTable;                                             //0xf8
    VOID* ProcessStarterHelper;                                             //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    UCHAR Padding4[4];                                                      //0x134
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    VOID (*PostProcessInitRoutine)();                                       //0x230
    VOID* TlsExpansionBitmap;                                               //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    VOID* pShimData;                                                        //0x2d8
    VOID* AppCompatInfo;                                                    //0x2e0
    struct _UNICODE_STRING CSDVersion;                                      //0x2e8
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    VOID* SparePointers[4];                                                 //0x320
    ULONG SpareUlongs[5];                                                   //0x340
    VOID* WerRegistrationData;                                              //0x358
    VOID* WerShipAssertPtr;                                                 //0x360
    VOID* pUnused;                                                          //0x368
    VOID* pImageHeaderHash;                                                 //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled:1;                                     //0x378
            ULONG CritSecTracingEnabled:1;                                  //0x378
            ULONG LibLoaderTracingEnabled:1;                                //0x378
            ULONG SpareTracingBits:29;                                      //0x378
        };
    };
    UCHAR Padding6[4];                                                      //0x37c
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
    ULONGLONG TppWorkerpListLock;                                           //0x388
    struct _LIST_ENTRY TppWorkerpList;                                      //0x390
    VOID* WaitOnAddressHashTable[128];                                      //0x3a0
    VOID* TelemetryCoverageHeader;                                          //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x7b8
    union
    {
        ULONG LeapSecondFlags;                                              //0x7c0
        struct
        {
            ULONG SixtySecondEnabled:1;                                     //0x7c0
            ULONG Reserved:31;                                              //0x7c0
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x7c4
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

typedef struct _FILE_DISPOSITION_INFORMATION {
	BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, * PFILE_DISPOSITION_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS_
{
	// FileDirectoryInformation = 1,
	FileFullDirectoryInformation = 2,   // 2
	FileBothDirectoryInformation,   // 3
	FileBasicInformation,           // 4  wdm
	FileStandardInformation,        // 5  wdm
	FileInternalInformation,        // 6
	FileEaInformation,              // 7
	FileAccessInformation,          // 8
	FileNameInformation,            // 9
	FileRenameInformation,          // 10
	FileLinkInformation,            // 11
	FileNamesInformation,           // 12
	FileDispositionInformation,     // 13
	FilePositionInformation,        // 14 wdm
	FileFullEaInformation,          // 15
	FileModeInformation,            // 16
	FileAlignmentInformation,       // 17
	FileAllInformation,             // 18
	FileAllocationInformation,      // 19
	FileEndOfFileInformation,       // 20 wdm
	FileAlternateNameInformation,   // 21
	FileStreamInformation,          // 22
	FilePipeInformation,            // 23
	FilePipeLocalInformation,       // 24
	FilePipeRemoteInformation,      // 25
	FileMailslotQueryInformation,   // 26
	FileMailslotSetInformation,     // 27
	FileCompressionInformation,     // 28
	FileObjectIdInformation,        // 29
	FileCompletionInformation,      // 30
	FileMoveClusterInformation,     // 31
	FileQuotaInformation,           // 32
	FileReparsePointInformation,    // 33
	FileNetworkOpenInformation,     // 34
	FileAttributeTagInformation,    // 35
	FileTrackingInformation,        // 36
	FileIdBothDirectoryInformation, // 37
	FileIdFullDirectoryInformation, // 38
	FileValidDataLengthInformation, // 39
	FileShortNameInformation,       // 40
	FileIoCompletionNotificationInformation, // 41
	FileIoStatusBlockRangeInformation,       // 42
	FileIoPriorityHintInformation,           // 43
	FileSfioReserveInformation,              // 44
	FileSfioVolumeInformation,               // 45
	FileHardLinkInformation,                 // 46
	FileProcessIdsUsingFileInformation,      // 47
	FileMaximumInformation                   // 48
} FILE_INFORMATION_CLASS_, * PFILE_INFORMATION_CLASS_;

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationFile(
	IN  HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN  PVOID FileInformation,
	IN  ULONG Length,
	IN  FILE_INFORMATION_CLASS FileInformationClass
);


#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004

#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)