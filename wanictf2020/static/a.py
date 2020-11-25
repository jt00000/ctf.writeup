import gdb
gdb.execute('file ./static')
gdb.execute('b*0x400eda')
gdb.execute('r')
ans = ''
for i in range(0x30):
    rax = int(gdb.execute('p $rax', to_string=True).split(' = ')[1], 16)
    rdx = int(gdb.execute('p $rdx', to_string=True).split(' = ')[1], 16)
    ans += chr(rax^rdx^0x41)
    gdb.execute('c')
print("answer:", ans)
gdb.execute('q')


