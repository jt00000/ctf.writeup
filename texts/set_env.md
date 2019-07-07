# 環境構築メモ
インストールしたらやることを覚えられなくなってきたので。

## 共有フォルダ設定
VMのメニューでやる
## キーボード設定
```
sudo dpkg-reconfigure keyboard-configuration
```
Generic-105keyを選択

## pwntool, z3, angr, one_gadget
```
sudo apt install python-pip ruby gem
sudo pip install pwntools z3py angr
sudo gem install one_gadget
```

## peda, angelheap
```
cd ~
git clone https://github.com/longld/peda.git ~/peda
git clone https://github.com/scwuaptx/Pwngdb.git 
cp ~/Pwngdb/.gdbinit ~/
```

## pwn_debug(for PIE binary)
```
git clone https://github.com/ray-cp/pwn_debug
cd pwn_debug
sudo python setup.py install
```


