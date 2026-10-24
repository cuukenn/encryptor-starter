#!/usr/bin/env bash
# JMH 阈值检查（CI 用）：bench.json 由下列命令生成——
#   java -jar encryptor-bench/target/bench.jar -wi 2 -i 3 -f 1 -prof gc \
#        -rf json -rff encryptor-bench/target/bench.json
# 断言：
#   1) RSA 并行度：decryptFourThreads 吞吐 >= 2.5 x decryptSingleThread（防单锁串行回归）
#   2) bytes/op（gc.alloc.rate.norm）不超基线 +10%；首次运行写入基线 encryptor-bench/baseline.json
#   3) ECDH-ES 往返 vs RSA 同构往返：仅打印比值（informational，不设闸门——3x1s 迭代噪声可达 ±35%，当闸门只会假失败）
# 取数一律按「全限定 benchmark 名」精确匹配（不用后缀），避免新增同名/同尾名的基准被误取。
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
JSON="${1:-$DIR/target/bench.json}"
BASELINE="$DIR/baseline.json"
python3 - "$JSON" "$BASELINE" <<'PY'
import json, os, sys
path, base_path = sys.argv[1], sys.argv[2]
data = json.load(open(path))

PKG = "io.github.cuukenn.encryptor.bench."

def score(name):
    for b in data:
        if b["benchmark"] == PKG + name:
            return b["primaryMetric"]["score"]
    raise SystemExit("missing benchmark: " + name)

single = score("RsaParallelBenchmark.decryptSingleThread")
four = score("RsaParallelBenchmark.decryptFourThreads")
if four < 2.5 * single:
    raise SystemExit("FAIL: RSA parallelism 4 threads %.2f vs 1 thread %.2f (need >= 2.5x)" % (four, single))
print("OK: rsa parallelism %.2fx (>= 2.5x)" % (four / single))

# 3) ECDH-ES 往返 vs RSA 同构往返：仅打印比值（不设闸门）——3x1s 迭代下该比值噪声可达 ±35%，
#    实测约 1.4x（共享的编解码管线占大头，P-256 协商相对 RSA-2048 私钥运算省下的只是其中一段），
#    用噪声这么大的比值当 CI 闸门只会带来假失败。看趋势请用更长的迭代（-wi 3 -i 5）。
rsa_rt = score("E2eBenchmark.roundTrip")
ecdh_rt = score("EcdhEsBenchmark.ecdhRoundTrip")
print("INFO: ecdh-es roundTrip %.2fx rsa (informational only)" % (ecdh_rt / rsa_rt))

# 4) ReplayGuard 存储吞吐（informational）：E2e 基准无法携带 ReplayGuard（复用同一 compact），
#    该每请求必经路径的量级在此观察；并发比率异常（<2x）值得关注但同样不设闸门
try:
    rg1 = score("ReplayGuardBenchmark.verifySingleThread")
    rg4 = score("ReplayGuardBenchmark.verifyFourThreads")
    print("INFO: replay guard verify 1thr=%.0f/s 4thr=%.0f/s (%.2fx, informational only)" % (rg1, rg4, rg4 / rg1))
except SystemExit:
    print("INFO: ReplayGuardBenchmark scores absent (older bench.json), skipped")

def norm_bytes(name):
    for b in data:
        if b["benchmark"] == PKG + name:
            for name, metric in b.get("secondaryMetrics", {}).items():
                if name.endswith("gc.alloc.rate.norm"):
                    return metric["score"]
    raise SystemExit("missing gc.alloc.rate.norm for " + name)

current = norm_bytes("E2eBenchmark.roundTrip")
if not os.path.exists(base_path):
    json.dump({"bytesPerOp": current}, open(base_path, "w"), indent=2)
    print("baseline written: %.1f bytes/op" % current)
else:
    base = json.load(open(base_path))["bytesPerOp"]
    if current > base * 1.10:
        raise SystemExit("FAIL: bytes/op %.1f exceeds baseline %.1f by more than 10%%" % (current, base))
    print("OK: bytes/op %.1f (baseline %.1f, +%.1f%%)" % (current, base, (current - base) / base * 100))
PY
