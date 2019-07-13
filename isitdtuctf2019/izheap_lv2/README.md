# iz heap lv2
unsafe unlink わからんかったので書き留める。

## バイナリ概要
add, edit, delete, showが使えるメモ帳的なもの。アドレスと、サイズが保存される。削除も適切。

addおよびeditのデータ入力にoff by oneがある。

## 方針検討
heapのoff by oneは、次のチャンクサイズが0x100以上であれば、prev inuseビットをクリアすることができる。  
heapのfdを触れないのでdupは作れない。chunkの中には特に有用な情報もない。
libc-は2.27であるため、tcacheがある。
大きくfreeするとarenaアドレスは出るが、削除が適切なためアドレスが残らず、参照できない。
この場合に有用なのがtcacheを使い切ってからのunsafe unlink  
heapの管理部が0x602040から続いているので、この辺りを狙って書き換えればよい。
gotは書けないので、gotからのleakが終わったら、heapのhookを書き換える。
したがって方針は以下の通り。  
1. 最初に２つ小さめのchunkを用意
2. tcacheを使い切る
3. ２つめのchunkを削除
4. unlink用のペイロード（後述）で２つめのchunkを確保し直す
5. ３つめのchunkを削除して、unlink発動。（ここで２つめのchunkのアドレスが0x602030になる。）
6. ２つめのchunkを編集して、１つめのアドレスをgotに書き換え、リーク
7. 再び２つめのchunkを編集して、１つめのアドレスを今度はfree_hookへ
8. １つめのchunkを編集して、systemのアドレスを入力
9. 新しく内容が"/bin/sh"のchunkを追加し、削除すればシェルが立ち上がる

## unlink attack
### 成立条件
- 0x100のサイズを超えるチャンクを確保し、freeできる
- 直前のチャンクにoff by oneがある
- (多分)targetとなるアドレスの値が非０である
![test](isitdtuctf2019/izheap_lv2/2019-07-13_15-31.png)
![test](isitdtuctf2019/izheap_lv2/2019-07-13_15-32.png)



