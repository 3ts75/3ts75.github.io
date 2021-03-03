---
title: Custom GetProcAddress
date: 2021-03-03 19:53:00 +09:00
categories: [Windows, BendyBear]
tags: [Malware]
---

```cpp
typedef struct _IMAGE_EXPORT_DIRECTORY {
  DWORD   Characteristics;
  DWORD   TimeDateStamp;
  WORD    MajorVersion;
  WORD    MinorVersion;
  DWORD   Name;
  DWORD   Base;
  DWORD   NumberOfFunctions;
  DWORD   NumberOfNames;
  DWORD   AddressOfFunctions;
  DWORD   AddressOfNames;
  DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

```cpp
#include <Windows.h>
#include <iostream>
using namespace std;

template<typename T>
LPVOID CustomGetProcAddress(T hModule, LPCSTR lpProcName) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONGLONG)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((ULONGLONG)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	//PCHAR DllName = (PCHAR)((ULONGLONG)pDosHeader + pExport->Name);
	//DWORD NumberOfFunctions = pExport->NumberOfFunctions;
	DWORD NumberOfNames = pExport->NumberOfNames;
	PDWORD AddressOfFunctions = (DWORD*)((ULONGLONG)pDosHeader + pExport->AddressOfFunctions);
	PDWORD AddressOfNames = (DWORD*)((ULONGLONG)pDosHeader + pExport->AddressOfNames);
	PWORD AddressOfNameOrdinals = (WORD*)((ULONGLONG)pDosHeader + pExport->AddressOfNameOrdinals);

	PCHAR AddressOfName = nullptr;
	WORD AddressOfNameOrdinal = 0;
	LPVOID AddressOfFunction = nullptr;
	for (DWORD i = 0; i < NumberOfNames; ++i) {
		AddressOfName = (PCHAR)((ULONGLONG)pDosHeader + AddressOfNames[i]);
		if (strcmp(AddressOfName, lpProcName)) {
			continue;
		} else {
			AddressOfNameOrdinal = AddressOfNameOrdinals[i];
			AddressOfFunction = (LPVOID)((ULONGLONG)pDosHeader + AddressOfFunctions[AddressOfNameOrdinal]);
			return AddressOfFunction;
		}
	}

	return nullptr;
}

int main() {
	HMODULE hKernel32{ GetModuleHandleA("kernel32") };

	LPVOID AddAtomAGetProcAddress{ GetProcAddress(hKernel32, "AddAtomA") };
	LPVOID AddAtomACustomGetProcAddress{ CustomGetProcAddress(hKernel32, "AddAtomA") };

	if (AddAtomAGetProcAddress == AddAtomACustomGetProcAddress)
		cout << "[+] Success!" << endl;
	else
		cout << "[-] Failure!" << endl;

	return 0;
}
```

# Reference
[BendyBear: サイバースパイグループBlackTechとリンクされた新しい中国のシェルコード](https://unit42.paloaltonetworks.jp/bendybear-shellcode-blacktech/)
[5d1414b47d88e95ae6612d3fc211c29b35cc5db4a8a992f5e27cff5203ebf44b]()
[PE Format - Win32 apps](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
[GetProcAddress function (libloaderapi.h) - Win32 apps](https://docs.microsoft.com/ja-jp/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)