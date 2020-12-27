from pwn import *
context.log_level = 'debug'
r = remote('20.48.84.64', 20001)



for i in range(15):
    r.recvuntil('...\n')
    while(1):
        blob = r.recvuntil('\n', True).split(' ')
        s = 0
        m = 0
        for x in blob:
            print '@@: ', hex(int(x))
            s ^= int(x)
            if m < int(x):
                m = int(x)

        heap = blob.index(str(m))
        nex = s % 0x4
        print "AAAA", hex(nex)
        if len(blob) != 1:
            if m >= 3:
                select = (m - (m ^ nex)) % 4
            else:
                if nex == 3:
                    heap = blob.index(str(nex-1))
                    select = nex-2
                else:
                    heap = blob.index(str(nex))
                    select = nex
        else:
            select = nex
        print hex(s), hex(nex), hex(select)
        assert(select != 0) # its over

        if len(blob) == 1: 
            r.sendlineafter(']: ', str(select))
        else:
            r.sendlineafter(']: ', str(heap))
            r.sendlineafter(']: ', str(select))
        ret = r.recvuntil('\n')
        if 'Won!' in ret:
            break



