#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import sys
import base64
import hashlib
import time
from pwn import *

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    # print(time.time(), "solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break;
    # print(time.time(), "done.")

    r.sendlineafter(b'string S: ', base64.b64encode(solved))

def solve_lab1_4(r):
    n = r.recv()
    n = r.recv()
    n = r.recvline()
    n = r.recvline().decode().split(" ")[3]
    print(n)
    t = r.recvline()
    t = r.recvline()
    t = r.recvline()
    for i in range(int(n)):
        line = r.recvuntil(b'?').decode()
        print(line)
        line = line.split()
        print(line[-5])
        print(line[-4])
        print(line[-3])
        a = int(line[-5])
        b = int(line[-3])
        c = 0
        if line[3] == "+":
            c = a + b
        elif line[3] == "-":
            c = a - b
        elif line[3] == "*":
            c = a * b
        elif line[3] == "//":
            c = a // b
        elif line[3] == "%":
            c = a % b
        elif line[3] == "**":
            c = a ** b
        solved = c.to_bytes((c.bit_length() + 7) // 8, 'little')
        r.sendline(base64.b64encode(solved))
        
    
    # r.sendlineafter(b'? ', n)

if __name__ == '__main__':
    #r = remote('localhost', 10330);
    r = remote('up23.zoolab.org', 10363)
    solve_pow(r)
    solve_lab1_4(r)
    r.interactive()
    r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
