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
            if( this.targetSo2 ==true){
                var moduleBase = Process.findModuleByName("libMMProtocalJni.so");
            
            
                var hookCount = 0;

                Interceptor.attach(moduleBase.base.add(0x05D868), {
                    onEnter: function(args) {
                        log("packimport4")
                        logRaw(this.context.x1);
                        
                            this.context.x1 = (0x4231611b);
                            logRaw(this.context.x1);
     
                    }
                });

                Interceptor.attach(moduleBase.base.add(0x005C354), {
                    onEnter: function(args) {
                        log("packimport4")
                        logRaw(this.context.x1);
                        this.context.x1=(0x4231611b)
                      
                        logRaw(this.context.x1);
                     
                        }
                
                }); 
              
            }

 
if( this.targetSo ==true){

                var moduleBase = Process.findModuleByName("libwechatnetwork.so");
                Interceptor.attach(moduleBase.base.add(0x00000037D680  ), {
                    onEnter: function(args){
                        log("cgi1")
                        log(this.context.x0.readCString())
                       
                
                        
                    }
                });

                var sub_20D6AC_addr = moduleBase.base.add(0x00242944  );

                Interceptor.attach(sub_20D6AC_addr, {
                    onEnter: function(args) {
                        // 函数参数映射 (ARM64)
                        this.a1     = this.context.x0;               // 上下文对象
                        this.nonce  = args[1];                       // x1 = a2, nonce
                        this.nonceLen = args[2].toInt32();           // x2 = a3, nonce length
                        this.aad    = args[3];                       // x3 = a4, AAD pointer
                        this.aadLen = args[4].toInt32();             // x4 = a5, AAD length
                        this.input  = args[5];                       // x5 = a6, 输入数据（加密时为明文，解密时为密文+tag）
                        this.inputLen = args[6].toInt32();           // x6 = a7, 输入长度
                        this.outputBuf = args[7];                    // x7 = a8, 输出结构体指针
                
                        // 从上下文读取标志位 (偏移 0x20)
                        var flag = this.a1.add(32).readU8();
                        var op = (flag & 1) ? "ENCRYPT" : "DECRYPT";
                        this._op = op;
                
                        // 从上下文读取 tag 长度 (偏移 0x18)
                        this.tagLen = this.a1.add(0x18).readU32();
                
                        // 从上下文读取密钥指针 (偏移 0x50)
                        this.keyPtr = this.a1.add(0x50).readPointer();
                        // 密钥长度未知，通常 AES-128-GCM 为 16 字节，我们尝试打印 16 字节
                        this.keyLen = 16;
                
                        log("========================================");
                        log("[MMTLS AES-GCM] " + op + " @ sub_242944");
                        log("nonce ptr=0x" + this.nonce + " len=" + this.nonceLen);
                        log(toHexString(this.input, this.inputLen))
                        log("input ptr=0x" + this.input + " len=" + this.inputLen);
                    
                        log("tag length from context: " + this.tagLen);
                        if (this.aadLen > 0) {
                            log("AAD ptr=0x" + this.aad + " len=" + this.aadLen);
                        }
                
                        // 打印密钥
                        if (this.keyPtr.isNull()) {
                            log("!!! key pointer is NULL !!!");
                        } else {
                            log("--- key (assuming 16 bytes for AES-128) ---");
                            log(hexdump(this.keyPtr, { length: this.keyLen, ansi: false }));
                        }
                
                        // 打印 nonce
                        log("--- nonce hex ---");
                        log(hexdump(this.nonce, { length: this.nonceLen, ansi: false }));
                
                        // 打印输入数据，并区分加密/解密场景
                        if (op === "ENCRYPT") {
                            log("--- plaintext (input) ---");
                            log(hexdump(this.input, { length: this.inputLen, ansi: false }));
                        } else {
                            // 解密时，输入 = 密文 (inputLen - tagLen) + tag (tagLen)
                            var cipherLen = this.inputLen - this.tagLen;
                            log("--- ciphertext part (len=" + cipherLen + ") ---");
                            log(hexdump(this.input, { length: cipherLen, ansi: false }));
                            log("--- expected tag (last " + this.tagLen + " bytes) ---");
                            log(hexdump(this.input.add(cipherLen), { length: this.tagLen, ansi: false }));
                        }
                
                        // 打印 AAD
                        if (this.aadLen > 0) {
                            log("--- AAD ---");
                            log(hexdump(this.aad, { length: this.aadLen, ansi: false }));
                        }
                        
                    },
                
                    onLeave: function(retval) {
                        var err = retval.toInt32();
                        log("--- result ---");
                        log("retval=0x" + retval + " (" + err + ")");
                
                        if (err === 0) {
                            // 输出缓冲区结构: a8[1]=数据指针, a8[2]=数据长度
                            var outPtr = this.outputBuf.add(8).readPointer();
                            var outLen = this.outputBuf.add(16).readU32();
                
                            log("--- output buffer ---");
                            log("buf ptr=0x" + outPtr + " len=" + outLen);
                
                            if (this._op === "ENCRYPT") {
                                // 输出 = 密文 (outLen - tagLen) + tag (tagLen)
                                var cipherLen = outLen - this.tagLen;
                                log("--- ciphertext (len=" + cipherLen + ") ---");
                                log(hexdump(outPtr, { length: cipherLen, ansi: false }));
                                log("--- computed tag (last " + this.tagLen + " bytes) ---");
                                log(hexdump(outPtr.add(cipherLen), { length: this.tagLen, ansi: false }));
                            } else {
                                // 解密输出 = 明文（已无 tag）
                                log("--- plaintext (output) ---");
                                log(toHexString(outPtr, outLen))
                                log(hexdump(outPtr, { length: outLen, ansi: false }));
                            }
                        } else {
                            log("[ERROR] " + this._op + " failed with code " + err);
                        }
                        log("========================================");
                    }
                });



            }

if( this.targetSo3 ==true){


     
    // ============================================================
    // Hook sub_20D6AC (__Run) — 打印 req2buf 之前的原始数据
    // ============================================================
    var moduleBase = Process.findModuleByName("libwechatmm.so");
    Interceptor.attach(moduleBase.base.add(0xE46E4), {
        onEnter: function(args) {
            log("ecdh1111" );
            log(this.context.x1)
              logRaw(hexdump(this.context.x2.add(0x10).readPointer(), { length:this.context.x2.add(0x8).readU32(), ansi: false }));
                   logRaw(hexdump(this.context.x3.add(0x10).readPointer(), { length:this.context.x3.add(0x8).readU32(), ansi: false }));
                    logRaw(toHexString(this.context.x2.add(0x10).readPointer(), this.context.x2.add(0x8).readU32()));
                      logRaw(toHexString(this.context.x3.add(0x10).readPointer(), this.context.x3.add(0x8).readU32()));

        }
    });
    Interceptor.attach(moduleBase.base.add(0x00E66A4), {
        onEnter: function(args) {
           this.a1=args[0]
           this.a2=args[1]
           this.a3=args[2]
           this.a4=args[3]
           this.a5=args[4]
           logRaw("HDFk ")
           logRaw(toHexString(this.a2,0x20))

           logRaw(toHexString(this.a3.add(0x10).readPointer(),  this.a3.add(0x8).readU32()))
           logRaw(toHexString(this.a4.add(0x10).readPointer(),  this.a4.add(0x8).readU32()))




            },
            onLeave: function(retval) {
                logRaw("HDFkL ")
                logRaw(toHexString(this.a5.add(0x10).readPointer(),  this.a5.add(0x8).readU32()))

            }
            });
    Interceptor.attach(moduleBase.base.add(0x0E6158), {
        onEnter: function(args) {
            // ============================================================
            // AesGcmEncrypt @ crypto_util.cc:717
            // 参数映射 (ARM64, 共12个参数, x0-x7寄存器 + 4个栈参数):
            //   x0       = unused (a1, 未使用)
            //   x1 = iv        (a2)
            //   x2 = iv_len    (a3)
            //   x3 = key       (a4)
            //   x4 = key_len   (a5)  16=AES-128, 24=AES-192, 32=AES-256
            //   x5 = aad       (a6)
            //   x6 = aad_len   (a7)
            //   x7 = plaintext (a8)
            //   栈:
            //     sp+0x00 = plaintext_len (a9,  int)
            //     sp+0x08 = output*       (a10, std::string*)
            //     sp+0x10 = tag*          (a11, uint8_t*)
            //     sp+0x18 = tag_len       (a12, int)
            // 返回值: 0=成功, 0xFFFFFFFF=失败
            // ============================================================

            var sp = this.context.sp;

            this.iv        = args[1];
            this.iv_len    = args[2].toInt32();
            this.key       = args[3];
            this.key_len   = args[4].toInt32();
            this.aad       = args[5];
            this.aad_len   = args[6].toInt32();
            this.plaintext = args[7];

            this.plaintext_len = sp.add(0x00).readU32();
            this.outputPtr     = sp.add(0x08).readPointer();
            this.tag           = sp.add(0x10).readPointer();
            this.tag_len       = sp.add(0x18).readU32();

            var algo = this.key_len === 32 ? "AES-256-GCM" :
                       this.key_len === 24 ? "AES-192-GCM" :
                       this.key_len === 16 ? "AES-128-GCM" :
                       "UNKNOWN(" + this.key_len + ")";

            log("============ AesGcmEncrypt ENTER ============");
            log("algo: " + algo);
            log("key (" + this.key_len + " bytes): " + toHexString(this.key, this.key_len));
            log("iv  (" + this.iv_len  + " bytes): " + toHexString(this.iv,  this.iv_len));
            log("aad (" + this.aad_len + " bytes): " + (this.aad_len > 0 ? toHexString(this.aad, Math.min(this.aad_len, 64)) : "(none)"));
            log("plaintext (" + this.plaintext_len + " bytes):");
            if (this.plaintext_len > 0 && this.plaintext_len < 65536) {
                logRaw(hexdump(this.plaintext, { length: Math.min(this.plaintext_len, 256), ansi: false }));
                logRaw(toHexString(this.plaintext,   256));

            }
            log("tag_len: " + this.tag_len);

            // key 和 iv 的 hexdump
            if (this.key_len > 0 && this.key_len <= 64) {
                log("--- key dump ---");
                logRaw(hexdump(this.key, { length: this.key_len, ansi: false }));
            }
            if (this.iv_len > 0 && this.iv_len <= 64) {
                log("--- iv dump ---");
                logRaw(hexdump(this.iv, { length: this.iv_len, ansi: false }));
            }
        },

        onLeave: function(retval) {
            var err = retval.toInt32();
            log("============ AesGcmEncrypt LEAVE ============");
            log("retval: " + retval + " (" + (err === 0 ? "SUCCESS" : "FAILED") + ")");

            if (err === 0) {
                // ── 读取输出 ciphertext (std::string*) ──
                // GCC libstdc++ std::string 布局:
                //   *output & 1 == 1 → 堆分配: *(output+8)=长度, *(output+16)=数据指针
                //   *output & 1 == 0 → SSO:   长度 = *output >> 1, 数据 = output + 1
                try {
                    var strPtr = this.outputPtr;
                    var firstByte = strPtr.readU8();
                    var ctLen, ctPtr;
                    if (firstByte & 1) {
                        ctLen = strPtr.add(8).readU64();
                        ctPtr = strPtr.add(16).readPointer();
                    } else {
                        ctLen = firstByte >> 1;
                        ctPtr = strPtr.add(1);
                    }
                    log("ciphertext (" + ctLen + " bytes):");
                    if (ctLen > 0 && ctLen < 65536) {
                        logRaw(hexdump(ctPtr, { length: Math.min(ctLen, 256), ansi: false }));
                    }
                } catch(e) {
                    log("Error reading ciphertext: " + e.message);
                }

                // ── 读取 authentication tag ──
                if (this.tag_len > 0 && !this.tag.isNull() && this.tag_len <= 64) {
                    log("tag (" + this.tag_len + " bytes): " + toHexString(this.tag, this.tag_len));
                    log("--- tag dump ---");
                    logRaw(hexdump(this.tag, { length: this.tag_len, ansi: false }));
                }
            }
            log("===============================================");
        }
    });

    // ============================================================
    // AesGcmDecrypt — 解密 hook
    // 参数布局与加密完全相同, 区别:
    //   x7 = ciphertext (不是 plaintext)
    //   输出 = plaintext (解密后的明文)
    // offset: 搜索 crypto_util.cc 中 "AesGcmDecrypt" 函数
    //         函数开头: EVP_CIPHER_CTX_new → EVP_DecryptInit_ex
    //         下面 offset 需要根据实际 binary 确认!
    // ============================================================
    Interceptor.attach(moduleBase.base.add(0xE5C60), {
        onEnter: function(args) {
            // ============================================================
            // AesGcmDecrypt @ crypto_util.cc:852
            // 参数映射 (ARM64, 共12个参数, x0-x7寄存器 + 4个栈参数):
            //   x0       = unused (a1, 未使用)
            //   x1 = iv        (a2)
            //   x2 = iv_len    (a3)
            //   x3 = key       (a4)
            //   x4 = key_len   (a5)  16=AES-128, 24=AES-192, 32=AES-256
            //   x5 = aad       (a6)
            //   x6 = aad_len   (a7)
            //   x7 = ciphertext (a8)
            //   栈:
            //     sp+0x00 = ciphertext_len (a9,  int)
            //     sp+0x08 = tag*           (a10, uint8_t*)
            //     sp+0x10 = tag_len         (a11, int)
            //     sp+0x18 = output*         (a12, std::string*)
            // 返回值: 0=成功, 0xFFFFFFFF=失败
            // ============================================================

            var sp = this.context.sp;

            this.iv            = args[1];
            this.iv_len        = args[2].toInt32();
            this.key           = args[3];
            this.key_len       = args[4].toInt32();
            this.aad           = args[5];
            this.aad_len       = args[6].toInt32();
            this.ciphertext    = args[7];

            this.ciphertext_len = sp.add(0x00).readU32();
            this.tag            = sp.add(0x08).readPointer();
            this.tag_len        = sp.add(0x10).readU32();
            this.outputPtr      = sp.add(0x18).readPointer();

            var algo = this.key_len === 32 ? "AES-256-GCM" :
                       this.key_len === 24 ? "AES-192-GCM" :
                       this.key_len === 16 ? "AES-128-GCM" :
                       "UNKNOWN(" + this.key_len + ")";

            log("============ AesGcmDecrypt ENTER ============");
            log("algo: " + algo);
            log("key (" + this.key_len + " bytes): " + toHexString(this.key, this.key_len));
            log("iv  (" + this.iv_len  + " bytes): " + toHexString(this.iv,  this.iv_len));
            log("aad (" + this.aad_len + " bytes): " + (this.aad_len > 0 ? toHexString(this.aad, Math.min(this.aad_len, 64)) : "(none)"));
            log("ciphertext (" + this.ciphertext_len + " bytes):");
            if (this.ciphertext_len > 0 && this.ciphertext_len < 65536) {
                logRaw(hexdump(this.ciphertext, { length: Math.min(this.ciphertext_len, 256), ansi: false }));
                logRaw(toHexString(this.ciphertext,  this.ciphertext_len));
            } 
            log("tag (" + this.tag_len + " bytes): " + toHexString(this.tag, this.tag_len));
            log("tag dump:");
            logRaw(hexdump(this.tag, { length: this.tag_len, ansi: false }));

            // key 和 iv 的 hexdump
            if (this.key_len > 0 && this.key_len <= 64) {
                log("--- key dump ---");
                logRaw(hexdump(this.key, { length: this.key_len, ansi: false }));
            }
            if (this.iv_len > 0 && this.iv_len <= 64) {
                log("--- iv dump ---");
                logRaw(hexdump(this.iv, { length: this.iv_len, ansi: false }));
            }
            var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
                        var lines = ["[AesGcmDecrypt stack]"];
                        backtrace.slice(0, 15).forEach(function(addr, index) {
                            var module = Process.findModuleByAddress(addr);
                            if (module) {
                                var offset = addr.sub(module.base);
                                lines.push("  #" + index + ": " + module.name + "+" + offset + " (" + addr + ")");
                            } else {
                                lines.push("  #" + index + ": " + addr);
                            }
                        });
                        logRaw(lines.join("\n"));
        },

        onLeave: function(retval) {
            var err = retval.toInt32();
            log("============ AesGcmDecrypt LEAVE ============");
            log("retval: " + retval + " (" + (err === 0 ? "SUCCESS" : "FAILED") + ")");

            if (err === 0) {
                // ── 读取输出 plaintext (std::string*) ──
                // libc++ std::string 布局:
                //   *output & 1 == 1 → 堆分配: *(output+8)=长度, *(output+16)=数据指针
                //   *output & 1 == 0 → SSO:   长度 = *output >> 1, 数据 = output + 1
                try {
                    var strPtr = this.outputPtr;
                    var firstByte = strPtr.readU8();
                    var ptLen, ptPtr;
                    if (firstByte & 1) {
                        ptLen = strPtr.add(8).readU64();
                        ptPtr = strPtr.add(16).readPointer();
                    } else {
                        ptLen = firstByte >> 1;
                        ptPtr = strPtr.add(1);
                    }
                    log("plaintext (" + ptLen + " bytes):");
                    if (ptLen > 0 && ptLen < 65536) {
                        logRaw(hexdump(ptPtr, { length: Math.min(ptLen, 256), ansi: false }));
                        logRaw(toHexString(ptPtr, ptLen));
                    }
                } catch(e) {
                    log("Error reading plaintext: " + e.message);
                }
            }
            log("===============================================");
        }
    });


    Interceptor.attach(moduleBase.base.add(0xE0478 ), {
        onEnter: function(args) {
            log("Uncompress" );
            log(this.context.x2)
            logRaw(toHexString(this.context.x1, ( this.context.x2).toInt32()));
            logRaw(hexdump(this.context.x1, { length:0x100, ansi: false }));



        }

   
    });


    Interceptor.attach(moduleBase.base.add(0xE46E4), {
        onEnter: function(args) {
            log("ecdh" );
            log(this.context.x1)



        }

   
    });

    }




if( this.targetSo2 ==true){
        var moduleBase = Process.findModuleByName("libMMProtocalJni.so");
    
        Interceptor.attach(moduleBase.base.add(0x65F28 ), {
            onEnter: function(args) {
                log("qqqqqqqqqqqqqqqqqqqq")
                logRaw(toHexString(this.context.x1,   this.context.x2.toInt32()));
              
             
                }
        
        }); 
        Interceptor.attach(moduleBase.base.add(0x065F64), {
            onEnter: function(args) {
                log("qqqqqqqqqqqqqqqqqqqq")
                logRaw(toHexString(this.context.x1,   this.context.x2.toInt32()));
      
             
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

// setTimeout(function () {

//     Java.perform(function () {
// var g1 = Java.use("com.tencent.mm.network.g1");
// g1["U"].implementation = function (i, i2, i3, str, z0Var, bArr, i4) {
//     console.log(`g1.U is called: i=${i}, i2=${i2}, i3=${i3}, str=${str}, z0Var=${z0Var}, bArr=${bArr}, i4=${i4}`);
//     this["U"](i, i2, i3, str, z0Var, bArr, i4);
// };
    
//     });
//     }, 1000);
// var A8KEY_URL   = "https://open.weixin.qq.com/connect/confirm?uuid=08171VrI0IwvFa1O";   // ← 填扫码 URL, 例如 "https://open.weixin.qq.com/connect/confirm?uuid=xxx"
// var A8KEY_SCENE = 4;
// var A8KEY_CT    = 19;
// var A8KEY_CV    = 6;

// setTimeout(function () {
//     Java.perform(function () {
//         var rx3_p = Java.use("rx3.p");
//         console.log("[A8Key] onSceneEnd hook 已注册");

//         rx3_p.onSceneEnd.overload('int', 'int', 'java.lang.String', 'com.tencent.mm.modelbase.m1')
//         .implementation = function (errType, errCode, errMsg, scene) {
//             var t = scene ? scene.getType() : -1;
//             if (t !== 0xe9 && t !== 0x6a) {
//                 return this.onSceneEnd(errType, errCode, errMsg, scene);
//             }
//             console.log("[A8Key.onSceneEnd] type=0x" + t.toString(16) +
//                         " errType=" + errType + " errCode=" + errCode +
//                         " msg=" + errMsg);

//             if (errType === 0 && errCode === 0 && scene) {
//                 try {
//                     var reqResp = scene.getReqResp();
//                     if (reqResp) {
//                         var o = Java.cast(reqResp, Java.use("com.tencent.mm.modelbase.o"));
//                         var proto = o.a();
//                         console.log("[A8Key RESPONSE] proto=" + proto +
//                                     " class=" + proto.getClass().getName());
//                         var cls = proto.getClass();
//                         function readField(name) {
//                             try {
//                                 var f = cls.getDeclaredField(name);
//                                 f.setAccessible(true);
//                                 return f.get(proto);
//                             } catch (e) { return undefined; }
//                         }
//                         console.log("  d (url?)  = " + readField("d"));
//                         console.log("  e (desc?) = " + readField("e"));
//                         console.log("  f (int)   = " + readField("f"));
//                         console.log("  g         = " + readField("g"));
//                         console.log("  h         = " + readField("h"));
//                         console.log("  o         = " + readField("o"));
//                         console.log("  B         = " + readField("B"));
//                         console.log("  I         = " + readField("I"));
//                     }
//                 } catch (e) { console.log("[A8Key] parse err: " + e); }
//             }
//             return this.onSceneEnd(errType, errCode, errMsg, scene);
//         };
//         console.log("[A8Key] hooks ready");
//     });
// }, 2000);


// // ============================================================
// // A8Key 自动发送 — 定时任务 (仅主进程)
// // ============================================================
// function a8key_send() {
//     // 只在主进程执行，子进程跳过

//     if (!A8KEY_URL) {
//         console.log("[A8Key] URL 为空, 跳过自动发送");
//         return;
//     }

//     Java.perform(function () {
//         console.log("\n[A8Key] ====== 开始主动调用 send ======\n");
//         console.log("[A8Key.send] url=" + A8KEY_URL + " scene=" + A8KEY_SCENE +
//                     " codeType=" + A8KEY_CT + " codeVer=" + A8KEY_CV);

//         var requestId = Math.floor(Math.random() * 0x7fffffff);
//         var attempt = 0, maxAttempts = 5;

//         while (attempt < maxAttempts) {
//             try {
//                 attempt++;
//                 // 1. 创建 k0 (请求对象)
//                 var K0 = Java.use("com.tencent.mm.modelsimple.k0");
//                 var k0 = K0.$new(A8KEY_URL, 0);

//                 // 2. 反射逐层取出 z15.s53 (protobuf 请求体)
//                 var O   = Java.use("com.tencent.mm.modelbase.o");
//                 var M   = Java.use("com.tencent.mm.modelbase.m");
//                 var S53 = Java.use("z15.s53");

//                 var fe  = K0.class.getDeclaredField("e"); fe.setAccessible(true);
//                 var o   = Java.cast(fe.get(k0), O);
//                 var fa  = O.class.getDeclaredField("a");  fa.setAccessible(true);
//                 var m   = Java.cast(fa.get(o), M);
//                 var fa2 = M.class.getDeclaredField("a");  fa2.setAccessible(true);
//                 var s53 = Java.cast(fa2.get(m), S53);

//                 // 3. 设置 protobuf 字段
//                 s53["d"].value = 2;
//                 var xu = Java.use("z15.xq5").$new();
//                 xu["d"].value = A8KEY_URL;
//                 xu["e"].value = true;
//                 s53["i"].value = xu;
//                 s53["o"].value = A8KEY_SCENE;
//                 s53["w"].value = A8KEY_CT;
//                 s53["x"].value = A8KEY_CV;
//                 s53["y"].value = requestId;
//                 s53["s"].value = 0;
//                 var wq = Java.use("z15.wq5").$new();
//                 wq.d(Java.array('byte', []));
//                 s53["B"].value = wq;

//                 // 4. 发送网络请求
//                 var r1  = Java.use("tk0.j1").d();
//                 var req = Java.cast(k0, Java.use("com.tencent.mm.modelbase.m1"));
//                 r1.g(req);
//                 console.log("[A8Key.send] SENT type=0x" + req.getType().toString(16) +
//                             " requestId=" + requestId);
//                 return;  // 成功
//             } catch (e) {
//                 console.log("[A8Key.send] attempt " + attempt + "/" + maxAttempts +
//                             " failed: " + e);
//                 if (attempt < maxAttempts) {
//                     Java.use("java.lang.Thread").sleep(2000);
//                 }
//             }
//         }
//         console.log("[A8Key.send] ALL ATTEMPTS FAILED");
//     });
// }

// // 定时任务: 首次 5s 后触发, 之后每 30s 循环一次 (仅主进程)
// setTimeout(function () {
//     a8key_send();
//     setInterval(a8key_send, 900000);
// }, 5000);
var A8KEY_URL   = "https://open.weixin.qq.com/connect/confirm?uuid=08171VrI0IwvFa1O";   // ← 填扫码 URL, 例如 "https://open.weixin.qq.com/connect/confirm?uuid=xxx"
var A8KEY_SCENE = 4;
var A8KEY_CT    = 19;
var A8KEY_CV    = 6;

// ---- Hook onSceneEnd, 收 A8Key 响应 (最早注册) ----
setTimeout(function () {
    Java.perform(function () {
        var rx3_p = Java.use("rx3.p");
        console.log("[A8Key] onSceneEnd hook 已注册");

        rx3_p.onSceneEnd.overload('int', 'int', 'java.lang.String', 'com.tencent.mm.modelbase.m1')
        .implementation = function (errType, errCode, errMsg, scene) {
            var t = scene ? scene.getType() : -1;
            if (t !== 0xe9 && t !== 0x6a) {
                return this.onSceneEnd(errType, errCode, errMsg, scene);
            }
            console.log("[A8Key.onSceneEnd] type=0x" + t.toString(16) +
                        " errType=" + errType + " errCode=" + errCode +
                        " msg=" + errMsg);

            if (errType === 0 && errCode === 0 && scene) {
                try {
                    var reqResp = scene.getReqResp();
                    if (reqResp) {
                        var o = Java.cast(reqResp, Java.use("com.tencent.mm.modelbase.o"));
                        var proto = o.a();
                        console.log("[A8Key RESPONSE] proto=" + proto +
                                    " class=" + proto.getClass().getName());
                        var cls = proto.getClass();
                        function readField(name) {
                            try {
                                var f = cls.getDeclaredField(name);
                                f.setAccessible(true);
                                return f.get(proto);
                            } catch (e) { return undefined; }
                        }
                        console.log("  d (url?)  = " + readField("d"));
                        console.log("  e (desc?) = " + readField("e"));
                        console.log("  f (int)   = " + readField("f"));
                        console.log("  g         = " + readField("g"));
                        console.log("  h         = " + readField("h"));
                        console.log("  o         = " + readField("o"));
                        console.log("  B         = " + readField("B"));
                        console.log("  I         = " + readField("I"));
                    }
                } catch (e) { console.log("[A8Key] parse err: " + e); }
            }
            return this.onSceneEnd(errType, errCode, errMsg, scene);
        };
        console.log("[A8Key] hooks ready");
    });
}, 2000);

// ---- 5 秒后主动调用 send ----
setTimeout(function () {
    if (!A8KEY_URL) {
        console.log("[A8Key] URL 为空, 跳过自动发送");
        return;
    }

    Java.perform(function () {
        console.log("\n[A8Key] ====== 5s 已到, 开始主动调用 send ======\n");
        console.log("[A8Key.send] url=" + A8KEY_URL + " scene=" + A8KEY_SCENE +
                    " codeType=" + A8KEY_CT + " codeVer=" + A8KEY_CV);

        var requestId = Math.floor(Math.random() * 0x7fffffff);
        var attempt = 0, maxAttempts = 5;

        while (attempt < maxAttempts) {
            try {
                attempt++;
                // 1. 创建 k0 (请求对象)
                var K0 = Java.use("com.tencent.mm.modelsimple.k0");
                var k0 = K0.$new(A8KEY_URL, 0);

                // 2. 反射逐层取出 z15.s53 (protobuf 请求体)
                var O   = Java.use("com.tencent.mm.modelbase.o");
                var M   = Java.use("com.tencent.mm.modelbase.m");
                var S53 = Java.use("z15.s53");

                var fe  = K0.class.getDeclaredField("e"); fe.setAccessible(true);
                var o   = Java.cast(fe.get(k0), O);
                var fa  = O.class.getDeclaredField("a");  fa.setAccessible(true);
                var m   = Java.cast(fa.get(o), M);
                var fa2 = M.class.getDeclaredField("a");  fa2.setAccessible(true);
                var s53 = Java.cast(fa2.get(m), S53);

                // 3. 设置 protobuf 字段
                s53["d"].value = 2;
                var xu = Java.use("z15.xq5").$new();
                xu["d"].value = A8KEY_URL;
                xu["e"].value = true;
                s53["i"].value = xu;
                s53["o"].value = A8KEY_SCENE;
                s53["w"].value = A8KEY_CT;
                s53["x"].value = A8KEY_CV;
                s53["y"].value = requestId;
                s53["s"].value = 0;
                var wq = Java.use("z15.wq5").$new();
                wq.d(Java.array('byte', []));
                s53["B"].value = wq;

                // 4. 发送网络请求
                var r1  = Java.use("tk0.j1").d();
                var req = Java.cast(k0, Java.use("com.tencent.mm.modelbase.m1"));
                r1.g(req);
                console.log("[A8Key.send] SENT type=0x" + req.getType().toString(16) +
                            " requestId=" + requestId);
                return;  // 成功
            } catch (e) {
                console.log("[A8Key.send] attempt " + attempt + "/" + maxAttempts +
                            " failed: " + e);
                if (attempt < maxAttempts) {
                    Java.use("java.lang.Thread").sleep(2000);
                }
            }
        }
        console.log("[A8Key.send] ALL ATTEMPTS FAILED");
    });
}, 5000);

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
    
    Java.perform(function () {
        var UtilsJni = Java.use("com.tencent.mm.jni.utils.UtilsJni");
        UtilsJni["HybridEcdhDecrypt"].implementation = function (j, bArr) {
            console.log(`UtilsJni.HybridEcdhDecrypt is called: j=${j}, bArr=${bArr}`);
            let result = this["HybridEcdhDecrypt"](j, bArr);
            console.log(`UtilsJni.HybridEcdhDecrypt result=${result}`);
            return result;
        };

        
    })
    Java.perform(function () {
        var MMProtocalJni = Java.use("com.tencent.mm.protocal.MMProtocalJni");
        MMProtocalJni["genSignature"].implementation = function (i, bArr, bArr2) {
            console.log(`MMProtocalJni.genSignature is called: i=${i}, bArr=${bArr}, bArr2=${bArr2}`);
            let result = this["genSignature"](i, bArr, bArr2);
            console.log(`MMProtocalJni.genSignature result=${result}`);
            return result;


            
        };
        var c$p = Java.use("com.tencent.mm.normsg.c$p");
        c$p["aa"].implementation = function (i, i2, i3, bArr) {
            console.log(`c$p.aa is called: i=${i}, i2=${i2}, i3=${i3}, bArr=${bArr}`);
            let result = this["aa"](i, i2, i3, bArr);
            console.log(`c$p.aa result=${result}`);
            return result;
        };
   
    })
}, 1000);
