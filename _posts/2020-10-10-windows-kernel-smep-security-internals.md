---
title: Windows kernel SMEP mitigation internals and exploitation
author: MalWatch
date: 2020-10-10
categories: [Research, exploit development]
tags: [security research]
toc: true
---

Microsoft implemented SMEP (Supervisor Mode Execution Prevention) within the Windows kernel to help thwart malicious actors from being able to call back to user-mode allocated shellcode during a kernel exploitation (privilege escalation) attempts. Just like user-mode application and memory can be protected by a variety of mitigations, kernel memory has a few also. SMEP, kASLR, kCFG, and a few other techniques. 

When conducting Windows kernel exploit development, if an attack is utilizing a fairly standard exploitation technique, stack/integer overflow, UAF, etc. At some point, the attacker will try to allocate shellcode with a function like VirtualAlloc within user-mode, and then use their exploited vulnerability to call back to this shellcode, depending on the shellcode technique, they can then obtain a higher set of privileges, or something similar in nature. SMEP prevents this type of attack by blocking callbacks to user-mode memory from kernel mode.

## Windows SMEP internals

## Bypassing SMEP with kernel ROP

## Conclusion
