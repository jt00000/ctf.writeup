from pwn import *
context.log_level = 'debug'

choose = "12020213022"

r = process('./harmagedon')

# gdb.attach(r)
ans = ''
for i in range(11):
    r.recvuntil('[')
    char = r.recv(4)
    r.sendlineafter(']', char[int(choose[i])])
    ans += char[int(choose[i])]
print ans
r.interactive()
