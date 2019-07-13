# babyshellcode
seccomp問  
設定以下の通り
```(console)
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x02 0xffffffff  if (A != 0xffffffff) goto 0007
 0005: 0x15 0x00 0x01 0x00000025  if (A != alarm) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00000000  return KILL 
```
32bit命令使うやつは落ちる。alarmじゃないと落ちる。
バイパス無理っぽいなって思って、競技時間は終わった。
どうもフラグ読み込んでたらしい。

_INIT_1という関数に全部いた。ghidraだと見えない。  
処理内容はこんな感じ
```(c)
mmap(0xcafe000, 0x1000, 7);
fd = open('/flag');
read(fd, 0xcafe000, 0x30);
fd = open(/dev/urandom);
key = read(fd, 0xcafe050, 8);

for i = 0xcafe000; i < 0xcafe030; i+=8){
    *i = *i ^ key;
}
*(0xcafe050) = 0;
```
要するに8byeランダムに持ってきて、フラグを塗りつぶす。フラグは最初８文字が決まっているので、そこから鍵を戻して、フラグを戻した上で文字の一致を利用してフラグを特定する。  
具体的には、alarm(5)されているバイナリに対して、文字が一致していればタイムアウト、文字が一致していなければalarm(1)にして、タイムアウト前にalarmが発動するようにすれば、その差が出るようになる。

0xcafe000にrwxがあることには気づいたが、どこで処理されているかも分からなかった。
syscallがあるところはちゃんと見ないとだめということ。   
見たって拾える自信はないが。
```(console)
[+] Opening connection to 209.97.162.170 on port 2222: Done
trying:  39 th digit: 122 z
[*] Closed connection to 209.97.162.170 port 2222
[+] Opening connection to 209.97.162.170 on port 2222: Done
trying:  39 th digit: 123 {
[*] Closed connection to 209.97.162.170 port 2222
[+] Opening connection to 209.97.162.170 on port 2222: Done
trying:  39 th digit: 124 |
[*] Closed connection to 209.97.162.170 port 2222
[+] Opening connection to 209.97.162.170 on port 2222: Done
trying:  39 th digit: 125 }
ISITDTU{y0ur_sh3llc0d3_Sk!LL_s0_g00000d}
```
