# DEFCON 2019 qual writeup
## Team: PwnaSonic, Point: 450, Rank: 90

1問をアシストしてもらって解いたかたち
あとspeedrunを4つくらい
## Reducted Puzzle (108pt,122solve)
真っ黒gifで、ヘッダがアニメーションぽい。
分解のサイトに放り込むと形が異なる黒い絵が並んで絶望してknow_your_memに逃げた。  
チームの人がgifに色をつけてくれて、そこからは普通に解けた。感謝。  

とりあえず再び分解サイトに放り込んで、アニメーションの間隔を伸ばして、1枚ずつスクショを撮った。それを高速に変えると、八角形が回っているように見える。  

こんな感じ。  
*チラチラするので注意* 
https://github.com/jt00000/ctf.writeup/blob/master/texts/redacted-puzzle-%E9%AB%98%E9%80%9F.gif?raw=true

回ってるのは嫌がらせだとして、八角形だとわかれば頂点を１と０に見立てるのはありがちな流れ。最初の三角形の上のところを最初のビットとして、全３５枚をちまちまと紙に書き下した。  

あとはasciiだかbaseXXだかで終わりっしょ、始点だけ８パターン順方向逆方向やっとけば出る。と思ったら出ない。  
ミスったかなと思ったが、ビット列をぼんやり眺めていると、  
```10001100 01100011 11100...```  
こうも読める  
```10001 10001 10001...```  
defconのフラグヘッダは同じ文字が連続している ```OOO{furagu}```  
どう見ても5bit区切りです本当にありがとうございました。  
word bagガッツリしたに書いてるので無視しないでっていう話ですね。

```py
s = "10001100 01100011 11100100 01000110 10000101 00111101 01000010 10011000 11100000 11110100 10000000 00101101 01110010 00011100 00001000 10100101 11010111 01101110 10100110 10010001 10111100 10000100 10000001 10111001 11010100 00111011 11001110 11110010 00011110 10011101 11001001 11000111 01100101 00011110 10011111"
words = "+-=ABCDEFGHIJKLMNOPQRSTUVWXYZ_{}"

s = s.split(' ')
for i in range(8):
    stream = ''
    for j in s:
        tmp = j
        # tmp = j[::-1]
        tmp = j[i:] + j[:i]
        stream += tmp
    ans = ''
    for j in range(0, len(stream), 5):
        ans += words[int(stream[j:j+5], 2)]

    print ans
```
```bash
$ python solve.py 
OOO{FORCES-GOVERN+TUBE+FRUIT_GROUP=FALLREMEMBER_WEATHER}
AEAJQA+IMH=AANMG+CKLFL+NGLU_VQGAMBBNDZ_GLXL{HM-YPLEZRM-}
DHDWDDFT{NBTC+{Q+HXJPZ-+PWMYQDPD{FG+KWPQ_N_ZT{ATBZMWH{A{
JNKPLJOJ_BGJF-_E+ORWEV=+CT}EDKJJZRP+WQKDYCYGMZEJGV}=UZEZ
W+YBZW=VXJPFPAPM-AG=MNJ+IG{{JXNWWKB-ODXKTMT=}VLWQO{CKVMW
PCTGWPCNR_B-DEB{==PR_+V-TQ_JYS-PP{FA+KZXJ}JS_N_QEEZHWN}Q
BMJAQBI-G{F=JL-_B-CWV-V=KEXWUHIBCZNT+YOSWXWYW-YELIVSQ-}E
FXVUBF{=QVNRVZAXF=IAPANBXISQLR{FIW-J-UAHQSQUPA{LZQOYBA{M
```
```OOO{FORCES-GOVERN+TUBE+FRUIT_GROUP=FALLREMEMBER_WEATHER}```  

こういうときに張り切って全パターン書いたら最初で当たるから困る。

## Speedrun1
BOFからROPでreadしてexecveのやつ

## Speedrun2
BOFからlibcリークでmainに戻るやつ

## Speedrun3
0x1eの長さで前半と後半のxorが一致するやつ。  
0f05のあとどうでもいいので適当に埋める。

## Speedrun8
canary BFで出して、あと1問目と一緒

## やっててできなかったもの
*speedrun4*: ret addrがうごくぞ！！だるい！って思ってたら解かれた。自分が何やってるかの理解がいるね。静的解析修行不足定期  
結局bp潰せるだけだから、戻るところが多少揺れて、そこにret sled入れましょうという話に見えた。sled入れてたけどその後がまずかった。  
*speedrun5*: putsのgotをmainにしたんだったかな。最後one_gadget死っぽい落ち方ローカルでしてたから、いけるやろって思ってサーバに撃ったらputs書き変わってなくて泣きながら直そうとしたけど無理なんですよねえ。なんかバイナリが差し替わってたらしい。恐ろしい  
*babyheap*: Tcacheいい加減一回勝ちたい。サイズ壊して、dupは作れそうだけどlibcが分からんのぢゃってなって終わった。なんか確保してfreeするだけで出てくるそうですね。便利ですねtcache


## 宿題
speedrun全部、babyheap:必ず解く
