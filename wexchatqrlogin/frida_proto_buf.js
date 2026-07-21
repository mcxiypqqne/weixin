// 主动调用版本：带重试机制，应对 spawn 启动时内部状态未初始化的情况
setTimeout(function () {

    var MAX_RETRIES = 30;        // 最多重试 30 次
    var RETRY_INTERVAL = 2000;   // 每次间隔 2 秒
    var retryCount = 0;
    var done = false;

    function tryCallToProtoBuf() {
        if (done) return;

        Java.perform(function () {
            if (done) return;
            var found = false;

            Java.choose("w15.kg", {
                onMatch: function (instance) {
                    if (done) return;
                    found = true;
                    retryCount++;
                    console.log("[Active] #" + retryCount + " Found instance, calling toProtoBuf...");
                    try {
                        var result = instance.toProtoBuf();
                        console.log("[Active] toProtoBuf success, length = " + result.length);
                        done = true;  // 先标记完成，避免 send 抛异常导致继续重试

                        // 将 Java byte[] 转成 JS number[]，Frida 的 send() 才能接受
                        var len = result.length;
                        var jsBytes = [];
                        for (var i = 0; i < len; i++) {
                            jsBytes.push(result[i]);
                        }
                        send({ type: "proto_buf_result", length: len }, jsBytes);
                    } catch (e) {
                        console.log("[Active] #" + retryCount + " Error: " + e);
                        if (retryCount >= MAX_RETRIES) {
                            console.log("[Active] Max retries reached, giving up.");
                            send({ type: "proto_buf_error", message: e.toString() });
                            done = true;
                        }
                    }
                },
                onComplete: function () {
                    if (!found && !done) {
                        retryCount++;
                        console.log("[Active] #" + retryCount + " No instance found, waiting...");
                        if (retryCount >= MAX_RETRIES) {
                            console.log("[Active] Max retries reached, giving up.");
                            send({ type: "proto_buf_error", message: "Max retries exceeded, no instance found" });
                            done = true;
                        }
                    }
                }
            });
        });
    }

    // 立即尝试一次，之后每 RETRY_INTERVAL ms 重试
    tryCallToProtoBuf();
    var timer = setInterval(function () {
        if (done) {
            clearInterval(timer);
            return;
        }
        tryCallToProtoBuf();
    }, RETRY_INTERVAL);

}, 4000);
