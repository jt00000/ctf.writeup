# Seccon Beginners 2019 
こんな感じ。初めてグラフに残った。  
![list](https://github.com/jt00000/ctf.writeup/blob/master/secconbeginer2019/Screenshot%20from%202019-05-26%2014-34-39.png)

![rank](https://github.com/jt00000/ctf.writeup/blob/master/secconbeginer2019/Screenshot%20from%202019-05-26%2014-48-05.png)  
Pwnはできたけど、苦手分野が残ったかたち。  
Revは解けたが意味がわからないまま終わった。 
## Pwn memo
サイズ聞かれて、何か入れるやつ。マイナス入れてもいいので、-100くらいして適当に入れるとセグフォる。  
2.27特有のsystem走らないやつがあるので、retを一回噛ませてからwin funcを呼ぶ。

## Pwn shellcoder
```binsh```の5文字が使えない縛りのシェルコード。  ```/bin/sh\x00```をビット反転してfffffffとかとxorするようにシェルコードを書き換えた。

## Pwn oneline
2回入力を許されている。入力のバッファの下にファンクションポインタがおいてあるので、一度目で文字を繋いでリーク→2度目で上書きしてone_gadgetに置き換える  
リークは繋がなくてもリークしてくれるらしい。便利。

## Pwn babyheap
free -> freeが通る。書き込みをするためには中身がnullである必要があるが、それをやる関数もある。

2回freeして、free_hookを書き換える。

## Rev seccompare
文字列比較

## Rev leakage
やばそうな変換関数が見えるが、最後に1文字ずつxorして入力と比較しているので、retにbp貼って1文字ずつ特定していけば良い

## Rev Linear Operation
IDA見ながらangr回したらフラグ落ちてた

## Rev SecconPass
bssにTMQで始まるやつがフラグっぽいのでxorしてみたら、0x37393739〜で文字が出るのでそれで。なんか後ろの方がうまく復号されないからなんかまだあるのかなと思ったらアナウンスがあって、通せた。

## Misc containers
png読む

## Misc Dump
hexdumpで8進数でフラグを出力していて、つないで復元して解凍したら画像が出る

## Misc Sliding puzzle
3x3のマスに1~8の数字があってきれいに並べるやつ。ソルバを探してそこからコマンドを生成した。100回やったらフラグ。

## Crypto So Tired
gzip解凍のb64のを1000回くらい繰り返した

## Crypto Party
連立方程式作ってz3でやった。もう少しまともな方法がありそう。

## Web Ramen
SQLi。```#```がコメントで使える。  
とりあえずテーブル名を探す。
```' UNION SELECT null, table_name from INFORMATION_SCHEMA.COLUMNS#```

```
名前 	一言
せくこん太郎 	1970 年よりラーメン道一本。美味しいラメーンを作ることが生きがい。
せくこん次郎 	せくこん太郎の弟。好きな食べものはコッペパン。
せくこん三郎 	せくこん次郎の弟。食材本来の味を引き出すことに全力を注ぐ。

    （略）

	INNODB_SYS_TABLES
	INNODB_BUFFER_POOL_STATS
	INNODB_FT_CONFIG
	flag
	members
```

普通にフラグだ。あとは見るだけ。  
```' UNION SELECT *,null from flag#```
```
ctf4b{a_simple_sql_injection_with_union_select}
```

## Web katsudon
b64





---
よくがんばりました。
