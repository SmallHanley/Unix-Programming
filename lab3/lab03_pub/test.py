from pwn import *
elf = ELF('./chals')
for g in elf.got:
   if "code_" in g:
      print("0x{:<x},".format(elf.got[g]))