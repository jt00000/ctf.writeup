# 学んだ
バッファリング。とりあえずprocess.PTYにしたら許される。

# 概要
競技時間中は解けず。off-by-one null使えるだけで、うまく行かないまま終わった。  
バッファの問題が分かっておらず、スクリプト組むので詰んでたのもあって萎えてた。  

changeとfreeに負数が入る。  
changeはtIndex+idx --> trip[idx] --> destinationの部分を変える
したがって同じ構造のものがあれば書き換えられて、freeが同じ構造になっている。  
これなんなんだ？他のGOTも調べたけどfreeだけっぽい。  

0x401f30 --> 0x400578 --> 0x602018

後はtIndexが0x6020c0にあるので、引いて0x401f30になるように調整して、freeをwin funcに変えて終わり。  

