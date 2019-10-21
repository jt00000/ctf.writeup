# 学び
- glibc2.30でした。2.29tcacheの動きは似ていて、free時のbkになんかいる。どうでもいいけど普通にカスタムlibcだと思って解いてた。lazyもカスタムっぽかったので、何かの流行りかと思ってたがただの無知。
- heap_base + 0xa8にサイズ0x50のtcacheチャンクのリストの先頭が格納されていて、`malloc(0x50)`が呼ばれるとサイズが何だろうがそこに書かれたアドレスを取ってしまう。あとはいつもと同じ。同じチャンクがリストにあるとだめなので、気をつけつつ、`malloc()`は10回以下の縛りがあるのでそこも気をつけつつ。

# 解き方
9回mallocで、1/256で行けた。  
以下が方針と、()内が動作。m:malloc, f: free, e:editと読み替えて。
- heap_base+0xa8を取りに行く。(m, m, f, f, e, m, m)これが1/16
- heap_base+0x98に0x420サイズのチャンクを作る(f, f, e, m)
- 0x420チャンクの下の方にサイズを合わせて沿うように、0x21チャンクを2つ以上並べる。(f, f, e, m)
- heap_base+0xa0を指すポインタを作る(f, f, e, m)
- heap_base+0xa0をfree(f)
- heap_base+0xa8を編集してstdoutを指すようにする。(e, m)これが1/16
- stdoutに例のあれをいれてリーク(e)
- heap_base+0xa8を編集してnullにする(e)
- free_hookにsystem(f, e, m)
- "/bin/sh"を作ってfreeしておしまい。(e, f)
