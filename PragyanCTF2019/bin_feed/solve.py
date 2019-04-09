from pwn import *
from ctypes import *

r = process('./challenge1')

host = "159.89.166.12"
port = 9800
# r = remote(host, port)

gdb.attach(r, '''
fin
fin
fin
fin
fin
''') 

text = r.recvuntil(' ;\n')
print text
value = text.split('\n')[1].split(' ;')
v1 = int(value[0], 10)
v2 = int(value[1], 10)
v3 = int(value[2], 10)
print "parse:", v1, v2, v3

# v4 + v5 = v1
# v5 + v6 = v2
# v6 + v4 = v3

v4 = (v1 - v2 + v3) / 2
v5 = (v1 + v2 - v3) / 2
v6 = (v2 + v3 - v1) / 2
ans1 = v4
ans2 = v5
ans3 = v6
print "ans: ", v4, v5, v6

payload = ''
payload += str(ans1)
payload += '\x00' * (10 -len(str(ans1)))
payload += str(ans2)
payload += '\x00' * (10 -len(str(ans2)))
payload += str(ans3)
payload += '\x00' * (10 -len(str(ans3)))
r.sendline(payload)
r.interactive()

print r.recvuntil(' ;\n')
payload = ''
payload += str(ans2)
r.sendline(payload)

print r.recvuntil(' ;\n')
payload = ''
payload += str(ans3)
r.sendline(payload)


r.interactive()
r.close() 
