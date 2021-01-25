---
title: Windows anti-debugging and VM detection techniques
author: MalWatch
date: 2020-08-26
categories: [Malware, anti debugging]
tags: [anti debugging]
toc: true
---

## Introduction

Anti-debugging is common within semi-advanced malware families, preventing analysts and people from having the ability to take a look into the inner-workings on the code. Threat actors have taken advantage of this to make their malware harder to analyze. This article covers some of the popular techniques that malware and software developers may use to further complicate your malware analysis or reverse engineering session.

----

## Windows API abuse

Certain Windows API functions can be used to detect a debugging state within an application, it's very common for malware to utilize basic API functions in to dissuade analysts, and make malware analysis just a bit more difficult. Detecting that it's being debugged can lead to the application acting differently, or exiting upon debugger discovery.

## IsDebuggerPresent

The *IsDebuggerPresent* providing by the Windows API via kernel32.dll, it is one of the most basic techniques for detecting if your application is being debugged by a user-mode debugger.

```
BOOL IsDebuggerPresent();
```

- https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent

*IsDebuggerPresent* works by checking the BeingDebugged flag within the processes PEB (Process Environment Block), if the application is indeed being debugged, the BeingDebugged flag gets set to 1, if the application is not being debugged, the BeingDebugged flag gets set to 0. This function simply checks the PEB flag and can determine if the application is being debugged or not.

We can observe this via a simple C++ application that calls the IsDebuggerPresent function while being debugged in WinDBG.

```c
0:000> dt _peb @$peb
ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
```
The source code for this is below.

```c++
#include <Windows.h>
#include <stdio.h>

int main(){

    if (IsDebuggerPresent()){
        MessageBoxA(NULL, "Debugger detected", "Notification", MB_OK);
        exit(1);
    } else {
	MessageBoxA(NULL, "Debugger is not present", MB_OK);
    }
    
    return 0;
}
```

## Timing checks

## RDTSC

## GetTickCount

## Virtual Machine detection

Malware that can detect if it's within a virtual machine can pose an interesting challenge for malware analysts. Malware may run differently if it detects that it is within a VM (meaning it's likely under analysis)

## Running processes

## Registry checks

## Hardware checks

## Malware analysis

## Conclusion
