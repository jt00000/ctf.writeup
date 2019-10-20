# 学び
諦めないこころ。  
revだけ1日半かけて、終了10分前で解けた。  
終わって2日くらいやり続けてpwnとmiscも解けた。  
上位チームは半日くらいで全部取ってたので、少なくとも解析にかかる時間を1/4にする必要がある。  

解析時間の短縮に当たり、方針が課題の１つ気がしていて、vm問で入力作らせる系は最初に絶対コマンド全部見て理解しておくべきだと思った。迷うから。試しに入れられるとなおよい  
あとアセンブラ書いてるチームあったけど、これはバグに悩まされて死にそうな気がするので、短期間の競技における方針としては正しくないかもと思っている。途中まで書いて挫折した。書けたら強いのかも。

## 絵文字
最終的に以下のようになった。 
```
0x01, 0x1f233, 🈳, nop
0x02, 0x02795, ➕, [reg-1] = [reg]+[reg-1]; reg = reg - 1
0x03, 0x02796, ➖, [reg-1] = [reg]-[reg-1]; reg = reg - 1
0x04, 0x0274c, ❌, [reg-1] = [reg]*[reg-1]; reg = reg - 1
0x05, 0x02753, ❓, [reg-1] = [reg]%[reg-1]; reg = reg - 1
0x06, 0x0274e, ❎, [reg-1] = [reg]^[reg-1]; reg = reg - 1
0x07, 0x1f46b, 👫, [reg-1] = [reg]&[reg-1]; reg = reg - 1
0x08, 0x1f480, 💀, if [reg] < [reg-1] then [reg-1]=1 else [reg-1]=0;reg = reg - 1
0x09, 0x1f4af, 💯, if [reg] == [reg-1] then [reg-1]=1 else [reg-1]=0;reg = reg - 1 
0x0a, 0x1f680, 🚀, jmp to reg
0x0b, 0x1f236, 🈶, if [reg-1] == 0 then reg = reg-2 else ip = reg, reg = reg-2
0x0c, 0x1f21a, 🈚, if [reg-1] == 0 then ip = reg, reg = reg-2 else reg = reg-2 
0x0d, 0x023ec, ⏬, reg+1 = ip+1; ip+=2
0x0e, 0x1f51d, 🔝, reg-=1
0x0f, 0x1f4e4, 📤, [reg+1] = buf[[reg]][reg-1]; reg+=1
0x10, 0x1f4e5, 📥, buf[[reg]][reg-1] = [reg-2]; reg-=3
0x11, 0x1f195, 🆕, malloc([reg]); reg-=1
0x12, 0x1f193, 🆓, free([reg]); reg-=1
0x13, 0x1f4c4, 📄, read(0, buf[reg], len(buf[reg])); reg-=1
0x14, 0x1f4dd, 📝, write(1, buf[reg], len(buf[reg])); reg-=1
0x15, 0x1f521, 🔡, dump reg until null
0x16, 0x1f522, 🔢, printf("%d", [reg])
0x17, 0x1f6d1, 🛑, exit()

0x00, 0x1f600, 😀
0x01, 0x1f601, 😁
0x02, 0x1f602, 😂
0x03, 0x1f923, 🤣
0x04, 0x1f61c, 😜
0x05, 0x1f604, 😄
0x06, 0x1f605, 😅
0x07, 0x1f606, 😆
0x08, 0x1f609, 😉
0x09, 0x1f60a, 😊
0x0a, 0x1f60d, 😍
```
これを見ながら絵文字プログラミングを楽しみます。

## rev
絵文字を解釈しているところから絵文字とその動きを特定する。  
この後は、比較をやる絵文字に対してブレークかけて比較値を見る方針が良さそう。  
これによると、まず入力が```XXXX-XXXX-XXXX-XXXX-XXXX```のフォーマットであるかどうかをチェックする。  
Xには任意の文字が入る。

次に1文字ごとに比較を取っていく。演算用にテーブルがあるようで、文字がそのまま比較されるわけではない。   
比較関数でブレークして、合うように文字を変えて調整した。

```
$ ./emojivm chal.evm 
*************************************
*                                   *
*             Welcome to            *
*        EmojiVM 😀😁🤣🤔🤨😮       *
*       The Reverse Challenge       *
*                                   *
*************************************

Please input the secret: plis-g1v3-me33-th3e-f14g
😍
hitcon{R3vers3_Da_3moj1}
```

世の中にはgdb scriptがあって、それを使って解くのがまっとうなやり方だと思うので習得する。

## misc
９ｘ９の掛け算を表示できたら勝ち。競技時間はほぼ未着手。  
```
1 * 1 = 1
1 * 2 = 2
...
```
解答のファイルをそのまま入力して表示したら？  
→この問題のemojivmだけは実行後の入力を受け付けない。(pwnの流用を防ぐため)

出力内容を全部絵文字にしたら？  
→文字が足らん（2000byte）

ということで、４つのバッファに分けて、
- 左の数字
- ```" * "```
- 右の数字
- ```" = "```
- ```\x0a```

としてまっとうに二重ループを組み立てた。
```
[*] Switching to interactive mode
[DEBUG] Received 0x1 bytes:
    '\n'

[DEBUG] Received 0x55 bytes:
    "Good job ! Here's the flag:\n"
    'hitcon{M0mmy_I_n0w_kN0w_h0w_t0_d0_9x9_em0j1_Pr0gr4mM!ng}\n'
```

## pwn
シェル取るだけ。こちらも未着手。  
スタックになってる部分の負のところ、いくつかの命令には-1になったらエラーにするものがあるが、条件分岐などで減るものについてはお咎めがない。  
スタックより若いところに何があるのかというと、バッファのポインタが並んでいる。  
任意のサイズでバッファを確保できるので、0x420のチャンクをフリーさせて、ポインタを復元してリークさせ、tcache dupを作ってfree("/bin/sh")の形に持っていった。
```
[+] Opening connection to 3.115.176.164 on port 30262: Done
[+] Starting local process '/bin/sh': pid 6671
[*] Stopped process '/bin/sh' (pid 6671)
heap: 0x55d751ba2e10
libc: 0x7f8240185000
[*] Switching to interactive mode
...
$ cat f*
hitcon{H0p3_y0u_Enj0y_pWn1ng_th1S_3m0j1_vM_^_^b}
```
