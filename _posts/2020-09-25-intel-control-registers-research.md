---
title: Intel Control registers security research
author: MalWatch
date: 2020-09-25
categories: [Research, exploit development]
tags: [security research]
toc: true
---

Intel Control registers are a type of Processor register, Intel's control registers serve the purpose of changing or controlling the behavior of the CPU. Certain registers can affect things like memory paging, interrupt control, and the modes that addressing is handled. Each control registers includes multiple "flags", which when are talked about, get appended to the register name. Intel's x64 series includes registers CR0 through CR4, beyond that are some more uncommon types of registers. The x86_64 series add a few more additional, and rare registers. CR = Control Register and the registers are acknowledged via their numerical number, CR0, CR1, CR2, etc.

Like all things, since the registers can have a large impact on certain functionality of how CPUs workn, certain registers have a history of being included in malware and exploits. With the amount of power that a single register can have over parts of memory, changing certain flags can easily be abused.

## Control register internals

### Control Register 0 (CR0)

### Control Register 0 (CR1)

### Control Register 0 (CR2)

### Control Register 0 (CR3)

### Control Register 0 (CR4)

## CR4.SMEP and kernel exploitation abuse

## Malware using CR r/w

## Conclusion
