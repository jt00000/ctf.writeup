# tokenizer
解けなかったし着手もしてない。writeupごちです。 
## バイナリ概要
strsepを利用して、指定したデリミタを用いて、先に入力された文字列を分割して表示する。表示バッファをすべて使い切ると、末尾の部分にひっついたsaved rbpが見える。
strsepはデリミタに該当するバイトを\x00に変える。逆に読み込み中に\x00があるとそこで読み込みをやめる。
## 方針検討
NULL文字を入れるとそれ以上の分割を諦める仕様のため、バッファのすべてをNULLでない文字列で埋める必要がある。
狙いはrbpの下1バイトを\x00にすることでリターンアドレスをずらして、こっちがコントロールしているバッファに飛ばすこと。したがってこの時点で1/16のexploitになる。今回はデリミタを適当に\xa0としてペイロードを組み立てた。  
ropはret2mainで普通に組んで、あとで\x00を\xa0に変えて送りつけることで、rbpが\xa0だったときに同時に\x00に変えられ、リターンアドレスがずれて制御を奪える。  
バッファサイズは0x400なので、上の方はretで埋めた。  
一度\xa0を引ければ、mainに戻ったあとの次のデリミタは一意に決まってるっぽいので、それに合わせる。今回だと\x78にすれば良かった。
