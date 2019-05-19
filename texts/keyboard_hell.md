# キーボード設定のおまじない
 1. ```sudo dpkg-reconfigure keyboard-configuration```  
  出てくるUIに従ってGeneric105のキーボードを選択。左矢印で枠を抜けてOKに行ける。  
  これがたまにやっても効かないときがある。とても困る
 2. ```setxkbmap -layout jp```  
  最強の呪文。今のところ勝率100%

