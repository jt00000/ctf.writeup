from pwn import *
import string

f = open('./ans.txt')
stream = []
for row in f:
    stream.append(int(row[:-1]))


def check_stream(length):
    for i in range(length-1):
        output = int(r.recvuntil('\n').split(', ')[2])
        # print output, stream[i]

    output = int(r.recvuntil('\n').split(', ')[2])
    if output == stream[length-1]:
        print "find: " 
        return 0
    return 1
payload = 'zer0pts{'
bag = string.printable
cnt = 0
while(cnt < len(stream)):
    for c in bag:
        r = process('sh')
        r.sendline('python3 vm.py')
        r.sendlineafter('[4611686018427387903, 247905749270528, 28629151, 0, 1, 0, 0, 0, 0, 0]\n', payload+c)
        ret = check_stream(len(payload)+1)
        print payload+c, ret
        if ret == 0:
            payload += c
            cnt += 1
            break
        r.close()
    
    r.close()

r.interactive()


