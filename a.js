// dump1.js - Frida Agent 脚本
// console.log 全部改为 send()，消息统一发往 Python 层

// 获取进程名（主模块名）
// 统一的 send 包装，传入纯消息字符串即可
// function log(msg) {
//     send({ type: "info", msg: "[*] [" + _procName + "] " + msg });
// }
// function logRaw(msg) {
//     send({ type: "info", msg: msg });
// }
function log(msg) {
    console.log( msg);
}
function logRaw(msg) {
    console.log(msg);
}
function toHexString(buffer, length) {
    var hexParts = [];
    for (var i = 0; i < length; i++) {
        var byte = buffer.add(i).readU8();
        var hex = ('0' + byte.toString(16)).slice(-2).toUpperCase();
        hexParts.push(hex);
    }
    return hexParts.join(' ');
}

function getProcessName() {
    var modules = Process.enumerateModules();
    if (modules.length > 0) return modules[0].name;
    return Process.id.toString();
}

var _procName = getProcessName();





var sendAddr = Process.getModuleByName("libc.so").getExportByName("sendto");
log("sendto addr: " + sendAddr);

var fdMap = {};
var connectPtr = Process.getModuleByName("libc.so").getExportByName("connect");
// Interceptor.attach(connectPtr, {
//     onEnter: function(args) {
//         this.fd = args[0].toInt32();
//         var sockaddr = args[1];
//         var family = sockaddr.readU16();
//         if (family === 2) {
//             var port = sockaddr.add(2).readU16();
//             port = ((port & 0xff) << 8) | ((port >> 8) & 0xff);
//             var ipBytes = sockaddr.add(4).readByteArray(4);
//             var ipStr = new Uint8Array(ipBytes).join('.');
//             fdMap[this.fd] = ipStr + ':' + port;
//             log("connect " + ipStr + ':' + port);

//             var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
//             var lines = [];
//             backtrace.slice(0, 15).forEach(function(addr, index) {
//                 var module = Process.findModuleByAddress(addr);
//                 if (module) {
//                     var offset = addr.sub(module.base);
//                     lines.push("  #" + index + ": " + module.name + "+" + offset + " (" + addr + ")");
//                 } else {
//                     lines.push("  #" + index + ": " + addr);
//                 }
//             });
//             logRaw("[connect stack]\n" + lines.join("\n"));
//         }
//     }
// });

// Interceptor.attach(sendAddr, {
//     onEnter: function(args) {
//         this.fd = args[0].toInt32();
//         this.buffer = args[1];
//         this.len = args[2].toInt32();
//         this.flags = args[3].toInt32();
//         var peer = fdMap[this.fd] || "unknown";
//         log("\n[*] sendto() called\n    peer: " + peer + "\n    fd: " + this.fd + ", len: " + this.len + ", flags: " + this.flags);
//         logRaw(toHexString(this.buffer, this.len));
//         logRaw("    data:\n" + hexdump(this.buffer, { length: this.len, ansi: false }));

//         var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
//         var lines = ["[sendto stack]"];
//         backtrace.slice(0, 15).forEach(function(addr, index) {
//             var module = Process.findModuleByAddress(addr);
//             if (module) {
//                 var offset = addr.sub(module.base);
//                 lines.push("  #" + index + ": " + module.name + "+" + offset + " (" + addr + ")");
//             } else {
//                 lines.push("  #" + index + ": " + addr);
//             }
//         });
//         logRaw(lines.join("\n"));
//     },
//     onLeave: function(retval) {
//         log("    -> returned: " + retval.toInt32());
//     }
// });

// var recvAddr = Process.getModuleByName("libc.so").getExportByName("recvfrom");
// log("recv addr: " + recvAddr);

// Interceptor.attach(recvAddr, {
//     onEnter: function(args) {
//         this.fd = args[0].toInt32();
//         this.buffer = args[1];
//         this.len = args[2].toInt32();
//         this.flags = args[3].toInt32();
//     },
//     onLeave: function(retval) {
//         var receivedLen = retval.toInt32();
//         if (receivedLen > 0) {
//             log("\n[*] recv() SUCCESS\n    fd: " + this.fd + ", len: " + receivedLen);

//             logRaw(toHexString(this.buffer, receivedLen));
//             logRaw("    data:\n" + hexdump(this.buffer, { offset: 0, length: Math.min(receivedLen, 700), header: true, ansi: false }));

//             var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
//             var lines = ["[recv stack]"];
//             backtrace.slice(0, 15).forEach(function(addr, index) {
//                 var module = Process.findModuleByAddress(addr);
//                 if (module) {
//                     var offset = addr.sub(module.base);
//                     lines.push("  #" + index + ": " + module.name + "+" + offset + " (" + addr + ")");
//                 } else {
//                     lines.push("  #" + index + ": " + addr);
//                 }
//             });
//             logRaw(lines.join("\n"));
//         }
//     }
// });

// ============================================================
// Java hooks — 放到最后，等 Native hooks 先初始化完
// ============================================================



function tiaoshi()
{
function dumpAsUint32LE(ptr, count) {
    const bytes = ptr.readByteArray(count * 4);
    if (!bytes) return '';

    const u8 = new Uint8Array(bytes);
    const result = [];

    for (let i = 0; i < u8.length; i += 4) {
        // 小端组合: byte0 是最低字节
        const val = (u8[i] | (u8[i+1] << 8) | (u8[i+2] << 16) | (u8[i+3] << 24)) >>> 0;
        // 格式化成 0x 开头的完整 8 位十六进制（前导零补全）
        result.push('0x' + val.toString(16).padStart(8, '0').toUpperCase());
    }

    return result.join(', ');
}


function toHexString1(buffer, length) {
    var hexParts = [];
    for (var i = 0; i < length; i++) {
        var byte = buffer.add(i).readU8();
    
        hexParts.push(byte);
    }
    return hexParts.join(',');
}
function toHexString(buffer, length) {
    var hexParts = [];
    for (var i = 0; i < length; i++) {
        var byte = buffer.add(i).readU8();
        var hex = ('0' + byte.toString(16)).slice(-2).toUpperCase();
        hexParts.push(hex);
    }
    return hexParts.join(' ');
}


function getFileName(fullPath) {
    if (!fullPath) return fullPath;
    var idx = fullPath.lastIndexOf('/');
    if (idx >= 0) return fullPath.substring(idx + 1);
    return fullPath;
}
Process.setExceptionHandler(exception => {
    if (exception.module && exception.module.name.includes("oat")) {
        console.error("[CRITICAL] ART运行时崩溃!");
        console.error("崩溃地址:", exception.address);
        
        // 尝试获取Java堆栈
        try {
            console.log(Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Exception").$new()
            ));
        } catch (e) {
            console.error("无法获取Java堆栈:", e);
        }
    }
    return false;
    });
Interceptor.attach(Module.getGlobalExportByName('android_dlopen_ext'), {
            onEnter: function(args) {
                var pathptr = args[0];
                if (pathptr && !pathptr.isNull()) {
                    var path = ptr(pathptr).readCString();
                    // console.log("[*] 加载: " + path);
                            var fileName = getFileName(path);
            // console.log("[*] 加载: " + fileName);
                                var mod33= Process.findModuleByName(fileName);
                                // if(mod33){          console.log("qweqw");                        console.log(mod33.base.toString(16))}
                                // else{
                                //         //  console.log("1231232131");
                                // }

                    if (path.includes('libwechatnetwork.so')) {
                        this.targetSo = true;

                        
                    console.log("[+] 进入10秒暂停状态...");

                        console.log("[+] 发现目标SO!");
                    }
                if (path.includes('libwechatbase.so')) {
                        this.targetSo1 = true;

                        
                    console.log("[+] 进入10秒暂停状态...");

                        console.log("[+] 发现目标SO!");
                    }
                    if (path.includes('libMMProtocalJni.so')) {
                        this.targetSo2 = true;

                        
                    console.log("[+] 进入10秒暂停状态...");

                        console.log("[+] 发现目标SO!");
                    }
                    if (path.includes('libwechatmm.so')) {
                        this.targetSo3 = true;

                        
                    console.log("[+] 进入10秒暂停状态...");

                        console.log("[+] 发现目标SO!");
                    }
                    if (path.includes('libcrypto.so')) {
                        this.targetSo4 = true;

                        
                    console.log("[+] 进入10秒暂停状态...");

                        console.log("[+] 发现目标SO!");
                    }
                    if (path.includes('libwechatnormsg.so')) {
                        this.targetSo5 = true;

                        
                    console.log("[+] 进入10秒暂停状态...");

                        console.log("[+] 发现目标SO!");
                    }
     var mod1 = Process.findModuleByName("libart.so");


        }
    },
         onLeave: function(retval) {
            var mod1 = Process.findModuleByName("libart.so");
 


 console.log("qqqqqqqqqqqqqqqqqqqq")

if( this.targetSo2 ==true){
        var moduleBase = Process.findModuleByName("libMMProtocalJni.so");
    
        Interceptor.attach(moduleBase.base.add(0x65F28 ), {
            onEnter: function(args) {
                  console.log("qqqqqqqqqqqqqqqqqqqq")
                  console.log(toHexString(this.context.x1,   this.context.x2.toInt32()));
              
             
                }
        
        }); 
        Interceptor.attach(moduleBase.base.add(0x065F64), {
            onEnter: function(args) {
                  console.log("qqqqqqqqqqqqqqqqqqqq")
                  console.log(toHexString(this.context.x1,   this.context.x2.toInt32()));
      
             
                }
        
        }); 
        Interceptor.attach(moduleBase.base.add(0x07B548 ), {
            onEnter: function(args) {
                log("qqqqqqqqqqqqqqqqqqqq1")
                logRaw(toHexString(this.context.x1,   this.context.x2.toInt32()));
      
             
                }
        
        }); 
        
    }
    }
});


  
}



//dump_dex.js

tiaoshi();



setTimeout(function () {

    // Java.perform(function () {
    //     var UtilsJni = Java.use("com.tencent.mm.jni.utils.UtilsJni");

    //     // inner_encrypt_key
    //     var encryptKeyBytes = Java.array('byte', [
    //         0x23, 0x42, 0x01, 0x1D, 0xE1, 0x02, 0x14, 0x43,
    //         0x4D, 0xCC, 0x40, 0x90, 0x16, 0xD6, 0x0D, 0xD1,
    //         0xF0, 0xDE, 0xA7, 0x53, 0xE5, 0x29, 0x37, 0x97
    //     ]);
    //     var encryptCount = 0;

    //     UtilsJni["AesGcmEncryptWithCompress"].implementation = function (bArr, bArr2) {
    //         encryptCount++;
    //         console.log(`UtilsJni.AesGcmEncryptWithCompress call #${encryptCount}: bArr=${bArr}, bArr2=${bArr2}`);
    //         if (encryptCount === 10) {
    //             console.log(`>>> 10th call! Replacing key with inner_encrypt_key`);
    //             let result = this["AesGcmEncryptWithCompress"](encryptKeyBytes, bArr);
    //             console.log(`UtilsJni.AesGcmEncryptWithCompress result=${result}`);
    //             return result;
    //         }
    //         let result = this["AesGcmEncryptWithCompress"](bArr, bArr2);
    //         console.log(`UtilsJni.AesGcmEncryptWithCompress result=${result}`);
    //         return result;
    //     };

    //     // inner_decrypt_key
    //     var decryptKeyBytes = Java.array('byte', [
    //         0x95, 0xAC, 0xFB, 0x49, 0x73, 0xD1, 0xEB, 0x1D,
    //         0xAD, 0xC4, 0xF3, 0xEA, 0x49, 0xF2, 0x1A, 0xF7,
    //         0x2E, 0x72, 0xA3, 0x8A, 0x3A, 0x91, 0xD6, 0x17
    //     ]);
    //     var decryptCount = 0;

    //     UtilsJni["AesGcmDecryptWithUncompress"].implementation = function (bArr, bArr2) {
    //         decryptCount++;
    //         console.log(`UtilsJni.AesGcmDecryptWithUncompress call #${decryptCount}: bArr=${bArr}, bArr2=${bArr2}`);
    //         if (decryptCount === 10) {
    //             console.log(`>>> 10th call! Replacing key with inner_decrypt_key`);
    //             let result = this["AesGcmDecryptWithUncompress"](decryptKeyBytes, bArr2);
    //             console.log(`UtilsJni.AesGcmDecryptWithUncompress result=${result}`);
    //             return result;
    //         }
    //         let result = this["AesGcmDecryptWithUncompress"](bArr, bArr2);
    //         console.log(`UtilsJni.AesGcmDecryptWithUncompress result=${result}`);
    //         return result;
    //     };
    // });
    Java.perform(function () {
    var MMProtocalJni = Java.use("com.tencent.mm.protocal.MMProtocalJni");

    var packKeyBytes = Java.array('byte', [
        0xFE, 0x03, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x76, 0x78, 0xBD, 0xD0, 0x77, 0xFF, 0x00
    ]);
    var packCount = 0;

    MMProtocalJni["pack"].implementation = function (bArr, pByteArray, bArr2, i, bArr3, str, i2, i3, i4, bArr4, bArr5, i5, i6, i7, i8, i9, i10, i11) {
        packCount++;
        console.log(`MMProtocalJni.pack call #${packCount}: bArr=${bArr}, pByteArray=${pByteArray}, bArr2=${bArr2}, i=${i}, bArr3=${bArr3}, str=${str}, i2=${i2}, i3=${i3}, i4=${i4}, bArr4=${bArr4}, bArr5=${bArr5}, i5=${i5}, i6=${i6}, i7=${i7}, i8=${i8}, i9=${i9}, i10=${i10}, i11=${i11}`);
        if (packCount === -1) {
            console.log(`>>> 10th call! Replacing bArr2 with pack_key`);
            let result = this["pack"](bArr, pByteArray, packKeyBytes, i, bArr3, str, i2, i3, i4, bArr4, bArr5, i5, i6, i7, i8, i9, i10, i11);
            console.log(`MMProtocalJni.pack result=${result}`);
            return result;
        }
        let result = this["pack"](bArr, pByteArray, bArr2, i, bArr3, str, i2, i3, i4, bArr4, bArr5, i5, i6, i7, i8, i9, i10, i11);
        console.log(`MMProtocalJni.pack result=${result}`);
        return result;
    };


});
    Java.perform(function () {
        var UtilsJni = Java.use("com.tencent.mm.jni.utils.UtilsJni");
        UtilsJni["HybridEcdhEncrypt"].implementation = function (j, bArr) {
            console.log(`UtilsJni.HybridEcdhEncrypt is called: j=${j}, bArr=${bArr}`);
            let result = this["HybridEcdhEncrypt"](j, bArr);
            console.log(`UtilsJni.HybridEcdhEncrypt result=${result}`);
            return result;
    };
    })


}, 1000);
