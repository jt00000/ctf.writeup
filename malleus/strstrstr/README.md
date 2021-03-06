# Malleus CTF / strstrstr
## 学んだ
- ノート問でoff-by-oneでnullしか無いときの対処法
- w PIE, Full RERLRO

## リーク
malloc consolidateを使って、有効なチャンクを巻き込んでfreeすることで、UAFの状態を作り出す。  
以下のような構成にすれば良い。

#1 サイズ0x100  
#2 サイズ0x40  
#3 サイズ0x100  
#4 サイズ0x20  
#5 サイズ0x20  

#1と#3を揃えているのはtcacheに吸われないため。  
書いていないが事前にtcacheは使い切っておく。（0x420以上freeすればOK）
ここから#2を生かしつつ、#3をfreeしてconsolidateを使って#2をfreeされた状態にする。具体的に以下の手順を踏む。  

1. free(#1)
2. free(#2)
3. malloc(#2)  
  このペイロードが最重要で、'A'*0x30+p64(0x140)とする。これで0x38のサイズで書き込みされるため、off-by-one nullによって#3のチャンクのヘッダのprev_inuseビットが落ちる。  
  0x140は＃1と#2を足したサイズを書く。上にはこれだけのサイズがありますと宣言している。  
4. free(#3)  
  これで#1までconsolidateが走って、libcの値が#1のfdとbkに現れる。ところが#2は実際にはfreeされていないため、UAFの状態になっている。
  またこのとき、#6がない場合はエラーで落ちる。

上記手順の後に、#1のサイズ分だけチャンクを埋めると、ちょうど#2のところにlibcアドレスが合うようになって、showを使うとリークできる。

## 書き込み
リーク後の書き込みはlibc-2.27だと簡単で、サイズを気にする必要がない。tcacheが有効なサイズを適当に持ってこればいい。  
直後の書き込みは#2と同じポインタを指す。（これを#6とする）
1. free(#2)
2. free(#6)
3. malloc(#6) <- free_hook
4. malloc(#6) <- dummy
5. malloc(#6) <- libc_system

あとは"/bin/sh"を格納したノートをfreeすればsystemが走って終わり。  
