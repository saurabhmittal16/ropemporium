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

# takes string and bad characters and returns a good string
# with the number to XOR chars with as a tuple
# or None if no solution
def get_good_string(string, badchars):

	for i in range(128):
		temp = []
		count = 0
		for ch in string:
			new = chr(ord(ch) ^ i)
			temp.append(new)

			if new not in badchars:
				count += 1
			
			if count == len(string):
				return (i, ''.join(temp))
	
	return None

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