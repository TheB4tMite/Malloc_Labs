#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template mdriver
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'mdriver')

context.terminal = ['kitty']
if args.DBG:
    context.log_level = 'debug'

# ./exploit.py DBG - context.log_level = 'debug'
# ./exploit.py NOASLR - turn off aslr



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# MACROS
def s(a) : return p.send(a)
def sl(a) : return p.sendline(a)
def sa(a,b) : return p.sendafter(a,b)
def sla(a,b) : return p.sendlineafter(a,b)
def rv(a) : return p.recv(a)
def ru(a) : return p.recvuntil(a)
def ra() : return p.recvall()
def rl() : return p.recvline()
def cyc(a): return cyclic(a)
def inr() : return p.interactive()
def rrw(var, list) : [var.raw(i) for i in list]
def rfg(var,a) : return var.find_gadget(a)
def rch(var) : return var.chain()
def rdm(var) : return var.dump()
def cls() : return p.close()

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
b mm_init
b mm_malloc
b mm_free
b mm_coalesce
continue
'''.format(**locals())
'''b mm_alloc
b mm_fit
b mm_sbrk
b mm_free
b mm_coalesce
b mm_realloc
b mm_insert
b mm_detach'''

'''
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                        BEGIN EXPLOIT
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
'''
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
# FORTIFY:  Enabled

p = start(["-V","-f",sys.argv[1]])

# sl(b"echo '$$'")
# sl(b'cat flag.txt')
# ru(b'$$\n')
# flag = rl().decode()
# log.success(f"FLAG: {flag}")

inr()

