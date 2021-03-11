---
title: Custom GetModuleHandle
date: 2021-03-12 02:50:00 +09:00
categories: [Windows, BendyBear]
tags: [Malware]
---

# Structure
```cpp
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR {
	UNICODE_STRING DosPath;
	PVOID Handle;
}CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	PVOID StandardInput;
	PVOID StandardOutput;
	PVOID StandardError;
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
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	ULONG EnvironmentSize;
}RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
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
} PEB, * PPEB;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;
```

# Source

```cpp
#include <windows.h>

PPEB GetPeb(VOID)
{
#if defined(_WIN64)
	return (PPEB)__readgsqword(0x60);
#elif defined(_WIN32)
	return (PPEB)__readfsdword(0x30);
#endif
}

#include <iostream>
#include <string>
using namespace std;

LPVOID CustomSimpleGetModuleHandleW(PCWCHAR ModuleNameW) {
	PPEB Peb;
	LPVOID RetValue{ nullptr };
	Peb = (PPEB)GetPeb();

	PLDR_MODULE FirstModule{ (PLDR_MODULE)Peb->LoaderData->InLoadOrderModuleList.Flink };
	PLDR_MODULE NextModule{ FirstModule };

	do {
		NextModule = (PLDR_MODULE)NextModule->InLoadOrderModuleList.Flink;

		wstring name(NextModule->BaseDllName.Buffer, NextModule->BaseDllName.Length / sizeof(WCHAR));
		if (name.compare(ModuleNameW) == 0) {
			RetValue = NextModule->BaseAddress;
			break;
		}
		if (FirstModule == NextModule)
			break;
	} while (true);

	return RetValue;
}

LPVOID CustomSimpleGetModuleHandleA(const char* ModuleNameA) {
	DWORD ModuleNameSizeA{ strlen(ModuleNameA) };
	PWCHAR ModuleNameW{ new WCHAR[ModuleNameSizeA+1] };
	ZeroMemory(ModuleNameW, (ModuleNameSizeA + 1) * 2);

	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, ModuleNameA, ModuleNameSizeA, ModuleNameW, (ModuleNameSizeA+1) * 2);
	
	return CustomSimpleGetModuleHandleW(ModuleNameW);
}

int main(VOID) {
	wstring NameW{ L"ntdll.dll" };
	string NameA{ "ntdll.dll" };

	cout << GetModuleHandleW(NameW.c_str()) << endl;
	cout << CustomSimpleGetModuleHandleW(NameW.c_str()) << endl;
	cout << CustomSimpleGetModuleHandleA(NameA.c_str()) << endl;

	return 0;
}
```