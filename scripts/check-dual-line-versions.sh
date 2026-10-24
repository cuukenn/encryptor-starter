#!/usr/bin/env bash
# 双线版本同步守卫：javax 线（root project.version）与 boot3 线引用的 javax 版本必须一致。
# 防的是安全事件级漏车：core 发 1.0.x 修复而 boot3 线的 BOM/core 引用还钉在旧字面量上，
# 3.x 用户被静默钉死在带洞的 core。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

root_version=$(python3 - "$ROOT/pom.xml" <<'PY'
import re,sys
s=open(sys.argv[1]).read()
m=re.search(r'(?s)<project[^>]*>.*?<version>([^<]+)</version>', s)
print(m.group(1))
PY
)
prop_version=$(python3 - "$ROOT/pom.xml" <<'PY'
import re,sys
s=open(sys.argv[1]).read()
m=re.search(r'<encryptor\.javax\.line\.version>([^<]+)</encryptor\.javax\.line\.version>', s)
print(m.group(1) if m else 'MISSING')
PY
)
if [ "$root_version" != "$prop_version" ]; then
  echo "FAIL: root project.version=$root_version != encryptor.javax.line.version=$prop_version" >&2
  echo "      发版时两者必须同步 bump（boot3 线经 property 引用 javax 线制品）" >&2
  exit 1
fi

# 三个 boot3 pom 的 BOM import 必须引用 property（出现字面量 javax 版本即红）
for pom in encryptor-starters/encryptor-spring-boot3-starter/pom.xml \
           encryptor-starters/encryptor-web-boot3-starter/pom.xml \
           encryptor-starters/encryptor-gateway-boot3-starter/pom.xml; do
  if grep -A2 '<artifactId>encryptor-dependencies</artifactId>' "$ROOT/$pom" | grep -q "<version>${root_version}</version>"; then
    echo "FAIL: $pom 的 BOM import 使用字面量 ${root_version}，应使用 \${encryptor.javax.line.version}" >&2
    exit 1
  fi
  if ! grep -A2 '<artifactId>encryptor-dependencies</artifactId>' "$ROOT/$pom" | grep -q 'encryptor.javax.line.version'; then
    echo "FAIL: $pom 的 BOM import 未引用 encryptor.javax.line.version property" >&2
    exit 1
  fi
done
echo "OK: dual-line version sync (javax=$root_version, boot3 references via property)"
