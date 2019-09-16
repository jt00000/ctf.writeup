# 学んだ
tcache perthread struct  
heapの上の方いつもなんかあるなとは思ってたので、そこの理解が進んだ。

# 概要
7回に行動が限定されている。回数はスタックで管理されていて書き換え困難。  
素直に考えると
alloc -> free -> free -> alloc -> write -> alloc -> alloc -> write
で最後の関数でmallocが走って、malloc_hookが動作するが、8つ必要ということがわかる。
最初のallocが無ければ足りる＋libcはリークされていることから、libcのwritableを0x10刻みでfreeしたけどできなくて終了した。  
解答は0x3a0のサイズのチャンクを作ってfreeすると、ちょうどheap+0x50のところにサイズ0x100のチャンクができたように見える。この状態でheap+0x50をfreeして書き込むことで、ちょうどのこの位置がサイズ0x20のtcache pointerになっているので、次のallocをコントロールできる。  
alloc(0x3a0) -> free(0) -> free(heap+0x50) -> alloc(0xf0) -> write(malloc_hook) -> alloc(0x90) -> write(one_gadget)  

良問  
