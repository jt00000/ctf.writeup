with open('./prog.bin', 'rb') as f:
	inp = f.read()


bf = ['>', ']', '<', '[', ',', '.', '-', '+']
out = ''
for i in inp:
	out += bf[ord(i) & 0x7]
	
with open('./out.bf', 'w') as f:
	f.write(out)

