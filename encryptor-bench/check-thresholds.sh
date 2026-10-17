#!/usr/bin/env bash
# JMH 阈值检查（CI 用）：bench.json 由下列命令生成——
#   java -jar encryptor-bench/target/bench.jar -wi 2 -i 3 -f 1 -prof gc \
#        -rf json -rff encryptor-bench/target/bench.json
# 断言：
#   1) RSA 并行度：decryptFourThreads 吞吐 >= 2.5 x decryptSingleThread（防单锁串行回归）
#   2) bytes/op（gc.alloc.rate.norm）不超基线 +10%；首次运行写入基线 encryptor-bench/baseline.json
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
JSON="${1:-$DIR/target/bench.json}"
BASELINE="$DIR/baseline.json"
python3 - "$JSON" "$BASELINE" <<'PY'
import json, os, sys
path, base_path = sys.argv[1], sys.argv[2]
data = json.load(open(path))

def score(suffix):
    for b in data:
        if b["benchmark"].endswith(suffix):
            return b["primaryMetric"]["score"]
    raise SystemExit("missing benchmark: " + suffix)

single = score("decryptSingleThread")
four = score("decryptFourThreads")
if four < 2.5 * single:
    raise SystemExit("FAIL: RSA parallelism 4 threads %.2f vs 1 thread %.2f (need >= 2.5x)" % (four, single))
print("OK: rsa parallelism %.2fx (>= 2.5x)" % (four / single))

def norm_bytes(suffix):
    for b in data:
        if b["benchmark"].endswith(suffix):
            for name, metric in b.get("secondaryMetrics", {}).items():
                if name.endswith("gc.alloc.rate.norm"):
                    return metric["score"]
    raise SystemExit("missing gc.alloc.rate.norm for " + suffix)

current = norm_bytes("roundTrip")
if not os.path.exists(base_path):
    json.dump({"bytesPerOp": current}, open(base_path, "w"), indent=2)
    print("baseline written: %.1f bytes/op" % current)
else:
    base = json.load(open(base_path))["bytesPerOp"]
    if current > base * 1.10:
        raise SystemExit("FAIL: bytes/op %.1f exceeds baseline %.1f by more than 10%%" % (current, base))
    print("OK: bytes/op %.1f (baseline %.1f, +%.1f%%)" % (current, base, (current - base) / base * 100))
PY
