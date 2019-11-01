from pwn import *
# context.log_level = 'debug'

#TARGET = './target'
HOST = ''
PORT = 0

r = process(["gdb", "mathme"])
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
# r = remote(HOST, PORT)

# elf = ELF(TARGET)


def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))


r.sendlineafter('gdb-peda$', 'b*0x0000000000401545')
r.sendlineafter('gdb-peda$', 'r')
r.sendlineafter('numbers :', '1\n2\n3')
while(1):
    try:
        r.sendlineafter('gdb-peda$', 'x/i $pc')
        dump = r.recvuntil('gdb-peda$')[:-10] 
        if "jmp" not in dump:
            print dump.split('\n')[0] 
        if "No registers" in dump:
            break
        if "<" not in dump: 
            r.sendline('s')
        else:
            r.sendline('n')
    except:
        break
# r.sendline('q')
r.interactive()
r.close()
