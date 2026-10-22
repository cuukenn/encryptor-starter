#!/usr/bin/env bash
#
# javax-to-jakarta.test.sh — scripts/javax-to-jakarta.sh 的自测脚本。
# 覆盖四类场景（boot3 双线复制对的实际口径）：
#   T1 stdin 变换正确性：HttpServletRequest/AsyncContext 替换、javax.crypto 不动、
#      注释/字符串里的 javax.servlet 同口径替换、幂等（变换两遍结果一致）。
#   T2 web/starter 型纯机械复制对：--diff 全量 PASS（exit 0），pom.xml 差异被默认排除；
#      任意深度嵌套 pom.xml/.DS_Store 仍被 basename pattern 排除（非全路径精确相等）。
#   T3 --exclude glob 登记排除（logs/generated.* 一类扫掉）+ 严格后缀/ basename 语义（子串不放宽）
#      + 更深层含 Servlet API 文件的正确替换（exit 0）。
#   T4 漂移捕获：exit 1 且 DIFF 行定位到具体文件。
#   T5 gateway 型复制对：--expect-diff 登记命中 → exit 0；
#      漏登记 → exit 1 且 DIFF 定位漏登记文件；登记失真 → EXEMPT-PATTERN-UNMATCHED；
#      豁免文件在 copy 侧缺失 → MISSING IN COPY + exit 1。
#   T6 退出码语义：--help exit 0；未识别模式/目录不存在/mktemp 失败 exit 2。
#   T7 守卫加固回归：--expect-diff 命中文件的 EYE-DIFF 眼审输出与 EXEMPT-FILES-INSPECT
#      标记（不改变退出码语义）；--exclude spring.factories 的反向渗入断言——
#      boot3 侧已删除该文件 → PASS，重新引入 → SPRING-FACTORIES-CREEP + exit 1。
#
# 运行：bash scripts/javax-to-jakarta.test.sh   （全 PASS → exit 0）
#
# @author changgg
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
S="$SCRIPT_DIR/javax-to-jakarta.sh"

if [ ! -x "$S" ]; then
  echo "FAIL: 主脚本不存在或不可执行: $S" >&2
  exit 2
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/jx2j-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
LAST_OUT="$WORK/last.out"
LAST_RC=0

ok()   { PASS=$((PASS+1)); echo "PASS: $*"; }
fail() { FAIL=$((FAIL+1)); echo "FAIL: $*"; }

# 运行命令并记录退出码与输出（test 脚本自身不设 -e，自行检查退出码）。
run() {
  "$@" > "$LAST_OUT" 2>&1
  LAST_RC=$?
  return 0
}

assert_rc() {
  local want="$1" desc="$2"
  if [ "$LAST_RC" = "$want" ]; then
    ok "$desc (exit=$LAST_RC)"
  else
    fail "$desc —— 期望 exit=$want 实际 exit=$LAST_RC"
    echo "----- 输出（尾部 25 行）-----" >&2
    tail -n 25 "$LAST_OUT" >&2 || true
    echo "------------------------------" >&2
  fi
}

assert_out_contains() {
  local needle="$1" desc="$2"
  if grep -qF -- "$needle" "$LAST_OUT"; then
    ok "$desc"
  else
    fail "$desc —— 输出中未找到: $needle"
    echo "----- 输出（尾部 25 行）-----" >&2
    tail -n 25 "$LAST_OUT" >&2 || true
    echo "------------------------------" >&2
  fi
}

# 写入文本文件（每参数一行）。
put() {
  local file="$1"
  shift
  mkdir -p "$(dirname "$file")"
  printf '%s\n' "$@" > "$file"
}

# ============================================================
# 样例：Servlet API + javax.crypto + 注释 + 字符串 混合内容
# ============================================================
SAMPLE_IN="$WORK/sample.javax.java"
put "$SAMPLE_IN" \
  'package io.github.cuukenn.demo;' \
  '' \
  'import javax.servlet.http.HttpServletRequest;' \
  'import javax.servlet.AsyncContext;' \
  'import javax.servlet.ServletException;' \
  'import javax.crypto.Cipher;' \
  'import javax.crypto.spec.SecretKeySpec;' \
  '// comment: javax.servlet.http.HttpServletRequest 也在注释里出现（应替换）。' \
  'class Demo {' \
  '  void f(javax.servlet.http.HttpServletRequest req) throws Exception {' \
  '    String tip = "form 载体 jwe=..., 格言里 javax.servlet 保留与替换同口径";' \
  '    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");' \
  '    AsyncContext ac = req.startAsync();' \
  '    throw new ServletException("demo");' \
  '  }' \
  '}'

EXPECTED_OUT="$WORK/sample.jakarta.java"
put "$EXPECTED_OUT" \
  'package io.github.cuukenn.demo;' \
  '' \
  'import jakarta.servlet.http.HttpServletRequest;' \
  'import jakarta.servlet.AsyncContext;' \
  'import jakarta.servlet.ServletException;' \
  'import javax.crypto.Cipher;' \
  'import javax.crypto.spec.SecretKeySpec;' \
  '// comment: jakarta.servlet.http.HttpServletRequest 也在注释里出现（应替换）。' \
  'class Demo {' \
  '  void f(jakarta.servlet.http.HttpServletRequest req) throws Exception {' \
  '    String tip = "form 载体 jwe=..., 格言里 jakarta.servlet 保留与替换同口径";' \
  '    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");' \
  '    AsyncContext ac = req.startAsync();' \
  '    throw new ServletException("demo");' \
  '  }' \
  '}'

# ------------------------------------------------------------
echo "== T1: stdin 变换正确性 =="
run bash "$S" < "$SAMPLE_IN"
assert_rc 0 "T1.1 stdin 模式 exit 0"
bash "$S" < "$SAMPLE_IN" > "$WORK/t1.real.out"
if diff -u "$EXPECTED_OUT" "$WORK/t1.real.out" > "$WORK/t1.diff" 2>&1; then
  ok "T1.2 输出与期望逐字节一致"
else
  fail "T1.2 输出与期望不一致"
  cat "$WORK/t1.diff" >&2 || true
fi
bash "$S" < "$WORK/t1.real.out" > "$WORK/t1.twice.out"
if cmp -s "$WORK/t1.real.out" "$WORK/t1.twice.out"; then
  ok "T1.3 幂等：已变换内容再过一遍不变"
else
  fail "T1.3 幂等失败"
fi
if grep -qF 'javax.crypto.Cipher' "$WORK/t1.real.out" && grep -qF 'javax.crypto.spec.SecretKeySpec' "$WORK/t1.real.out"; then
  ok "T1.4 javax.crypto import 原样保留"
else
  fail "T1.4 javax.crypto 被误改"
fi
if grep -F 'javax.servlet' "$WORK/t1.real.out" > /dev/null 2>&1; then
  fail "T1.5 输出残留 javax.servlet"
else
  ok "T1.5 输出不含任何残留 javax.servlet"
fi

# ------------------------------------------------------------
echo "== T2: web/starter 型纯机械复制对 → 全量 PASS =="
BASE2="$WORK/web/base"
COPY2="$WORK/web/copy"
put "$BASE2/src/main/java/io/github/cuukenn/web/filter/F.java" \
  'package io.github.cuukenn.web.filter;' \
  'import javax.servlet.http.HttpServletRequest;' \
  'class F { Object c(HttpServletRequest r) { return r.getContentType(); } }'
put "$BASE2/src/main/resources/META-INF/spring.factories" \
  'org.springframework.boot.autoconfigure.EnableAutoConfiguration=\' \
  'io.github.cuukenn.web.configuration.WebEncryptorConfiguration'
put "$BASE2/src/main/java/io/github/cuukenn/web/NoJavax.java" \
  'package io.github.cuukenn.web;' \
  'class NoJavax { long f() { return 42L; } }'
# pom.xml 两侧刻意不同（boot3 模块 pom 结构差异是预期值，默认排除）。
put "$BASE2/pom.xml" '<project><artifactId>encryptor-spring-boot-starter</artifactId></project>'
put "$COPY2/pom.xml" '<project><artifactId>encryptor-spring-boot3-starter</artifactId><extra/></project>'

# 复制器的真实生成路径：逐文件 stdin 变换写入 copy 侧。
(cd "$BASE2" && find . -type f) | sed 's|^\./||' | while IFS= read -r rf; do
  mkdir -p "$COPY2/$(dirname "$rf")"
  bash "$S" < "$BASE2/$rf" > "$COPY2/$rf"
done

run bash "$S" --diff "$BASE2" "$COPY2"
assert_rc 0 "T2.1 纯机械对 --diff exit 0（pom.xml 差异默认排除）"
assert_out_contains "uniform=3" "T2.2 统计：3 个文件全量一致"

# 嵌套深度（Important 修复回归）：pom.xml/.DS_Store 是 basename/任意深度 pattern，不是全路径精确相等。
put "$BASE2/docs/pom.xml" '<project><artifactId>base-组内说明</artifactId></project>'
put "$COPY2/docs/pom.xml" '<project><artifactId>boot3-组内说明不同</artifactId></project>'
put "$COPY2/.meta/.DS_Store" 'junk'
run bash "$S" --diff "$BASE2" "$COPY2"
assert_rc 0 "T2.3 嵌套 pom.xml（双侧内容不同）与嵌套 .DS_Store 仍被默认排除 → exit 0"
assert_out_contains "uniform=3" "T2.4 统计仍 3（嵌套排除物未计入）"

# ------------------------------------------------------------
echo "== T3: --exclude 追加排除 + 深层 Servlet API 文件 =="
put "$BASE2/src/main/java/io/github/cuukenn/web/filter/Deep.java" \
  'package io.github.cuukenn.web.filter;' \
  'import javax.servlet.ServletOutputStream;' \
  'class Deep { ServletOutputStream out; }'
mkdir -p "$COPY2/src/main/java/io/github/cuukenn/web/filter"
bash "$S" < "$BASE2/src/main/java/io/github/cuukenn/web/filter/Deep.java" \
  > "$COPY2/src/main/java/io/github/cuukenn/web/filter/Deep.java"
# copy 侧多两个工件文件（不同扩展名），用 glob pattern --exclude 一次登记整类（Glob 生效回归）。
put "$COPY2/logs/generated.evict" 'boot3 生成工件，登记排除'
put "$COPY2/logs/generated.bin" '另一生成工件，同被 glob 覆盖'

run bash "$S" --diff "$BASE2" "$COPY2" --exclude 'logs/generated.*'
assert_rc 0 "T3.1 glob --exclude logs/generated.* 后 exit 0"
# 子串不命中（严格匹配语义回归）：pattern 含 '/' 走严格后缀，非后缀/非 basename 的子串不放宽。
run bash "$S" --diff "$BASE2" "$COPY2" --exclude 'b/generated.ev'
assert_rc 1 "T3.3 子串 pattern 不命中（严格后缀/basename 语义）→ exit 1"
if grep -qF 'import jakarta.servlet.ServletOutputStream;' "$COPY2/src/main/java/io/github/cuukenn/web/filter/Deep.java"; then
  ok "T3.2 深层文件 import 正确替换"
else
  fail "T3.2 深层文件 import 替换缺失"
fi

# ------------------------------------------------------------
echo "== T4: 漂移捕获 + 定位 =="
put "$COPY2/src/main/java/io/github/cuukenn/web/filter/F.java" \
  'package io.github.cuukenn.web.filter;' \
  'import jakarta.servlet.http.HttpServletRequest;' \
  'class F { Object c(HttpServletRequest r) { return r.getContentType(); } /* copy 侧漂移 */ }'
printf '%s\n' '// copy 侧追加行 → 模拟漂移' >> "$COPY2/src/main/java/io/github/cuukenn/web/NoJavax.java"

run bash "$S" --diff "$BASE2" "$COPY2"
assert_rc 1 "T4.1 漂移对 exit 1"
assert_out_contains "DIFF: src/main/java/io/github/cuukenn/web/filter/F.java" "T4.2 DIFF 行定位漂移文件 1"
assert_out_contains "DIFF: src/main/java/io/github/cuukenn/web/NoJavax.java" "T4.3 DIFF 行定位漂移文件 2"

# ------------------------------------------------------------
echo "== T5: gateway 型复制对 + --expect-diff 豁免 =="
GBASE="$WORK/gw/base"
GCOPY="$WORK/gw/copy"
GWPKG="src/main/java/io/github/cuukenn/encryptor/reactive/gateway/filter"
put "$GBASE/$GWPKG/EncryptorGatewayFilter.java" \
  'package io.github.cuukenn.encryptor.reactive.gateway.filter;' \
  'import javax.servlet.http.HttpServletRequest;' \
  'class EncryptorGatewayFilter {' \
  '  Object f(javax.servlet.http.HttpServletRequest req) {' \
  '    HttpMethod m = req.getMethodValue();' \
  '    return m;' \
  '  }' \
  '}'
put "$GBASE/$GWPKG/EncryptorResponseFilter.java" \
  'package io.github.cuukenn.encryptor.reactive.gateway.filter;' \
  'class EncryptorResponseFilter {' \
  '  Object f(javax.servlet.http.HttpServletRequest req) {' \
  '    return req.getStatusCode();' \
  '  }' \
  '}'
put "$GBASE/$GWPKG/Mechanical.java" \
  'package io.github.cuukenn.encryptor.reactive.gateway.filter;' \
  'import javax.servlet.AsyncContext;' \
  'class Mechanical { AsyncContext ac; }'

# copy 侧：Mechanical 走机械替换；另两个为"已知 Spring API 改写"（模拟 Task 5 的源码级修订）。
mkdir -p "$GCOPY/$GWPKG"
bash "$S" < "$GBASE/$GWPKG/Mechanical.java" > "$GCOPY/$GWPKG/Mechanical.java"
sed -e 's/javax\.servlet/jakarta.servlet/g' \
    -e 's/getMethodValue()/getMethod().name()/' \
    "$GBASE/$GWPKG/EncryptorGatewayFilter.java" > "$GCOPY/$GWPKG/EncryptorGatewayFilter.java"
sed -e 's/javax\.servlet/jakarta.servlet/g' \
    -e 's/getStatusCode()/getStatusCode().value()/g' \
    "$GBASE/$GWPKG/EncryptorResponseFilter.java" > "$GCOPY/$GWPKG/EncryptorResponseFilter.java"

GWPF="$GWPKG/EncryptorGatewayFilter.java"
GWPR="$GWPKG/EncryptorResponseFilter.java"

run bash "$S" --diff "$GBASE" "$GCOPY" --expect-diff "$GWPF" --expect-diff "$GWPR"
assert_rc 0 "T5.1 gateway 带 --expect-diff 登记命中 → exit 0"
assert_out_contains "EXEMPT: $GWPF" "T5.2 EXEMPT 行列出登记文件 1"
assert_out_contains "EXEMPT: $GWPR" "T5.3 EXEMPT 行列出登记文件 2"

assert_out_contains "differing=0 missing=0" "T5.4 未登记文件无漂移"

# 反例：漏登记 → DIFF 精确定位
run bash "$S" --diff "$GBASE" "$GCOPY" --expect-diff "$GWPF"
assert_rc 1 "T5.5 漏登记 response 过滤器 → exit 1"
assert_out_contains "DIFF: $GWPR" "T5.6 DIFF 行定位漏登记文件（人审入口）"

# 反例：登记 pattern 拼错 → EXEMPT-PATTERN-UNMATCHED 定位
run bash "$S" --diff "$GBASE" "$GCOPY" --expect-diff "$GWPF.jmsuffix"
assert_rc 1 "T5.7 登记失真（未命中任何文件）→ exit 1"
assert_out_contains "EXEMPT-PATTERN-UNMATCHED: --expect-diff ${GWPF}.jmsuffix" "T5.8 输出 EXEMPT-PATTERN-UNMATCHED 定位登记项"

# 反例：豁免文件在 copy 侧缺失（只生成了纯机械文件）→ 漂移 + MISSING 定位（豁免登记不掩盖缺失）
GONLY="$WORK/gw/partial-copy"
mkdir -p "$GONLY/$GWPKG"
bash "$S" < "$GBASE/$GWPKG/Mechanical.java" > "$GONLY/$GWPKG/Mechanical.java"
run bash "$S" --diff "$GBASE" "$GONLY" --expect-diff "$GWPF" --expect-diff "$GWPR"
assert_rc 1 "T5b.1 豁免文件在 copy 侧缺失 → exit 1"
assert_out_contains "MISSING IN COPY: $GWPF" "T5b.2 MISSING IN COPY 定位豁免文件 1"
assert_out_contains "MISSING IN COPY: $GWPR" "T5b.3 MISSING IN COPY 定位豁免文件 2"

# ------------------------------------------------------------
echo "== T6: 用法与退出码语义 =="
run bash "$S" --help
assert_rc 0 "T6.1 --help exit 0"
assert_out_contains "--expect-diff" "T6.2 help 列出 --expect-diff"
run bash "$S" --bogus-mode
assert_rc 2 "T6.3 未识别模式 exit 2"
run bash "$S" --diff "$WORK/nonexistent-dir" "$GCOPY"
assert_rc 2 "T6.4 base 目录不存在 exit 2"
run env TMPDIR="$WORK/absent-tmp" bash "$S" --diff "$GBASE" "$GCOPY"
assert_rc 2 "T6.5 mktemp 失败（TMPDIR 不可用）→ exit 2"

# ------------------------------------------------------------
echo "== T7: 守卫加固回归（EYE-DIFF 眼审输出 + spring.factories 反向渗入断言）=="
# T7 建独立 fixture（EYES/EYEC：豁免文件 2 + 纯机械 1），不污染前面节的 fixture。
EYES="$WORK/eye/base"
EYEC="$WORK/eye/copy"
EYPKG="src/main/java/io/github/cuukenn/encryptor/eye/filter"
put "$EYES/$EYPKG/EyeExemptOne.java" \
  'package io.github.cuukenn.encryptor.eye.filter;' \
  'import javax.servlet.http.HttpServletRequest;' \
  'class EyeExemptOne {' \
  '  Object f(javax.servlet.http.HttpServletRequest req) {' \
  '    return req.getStatusCode();' \
  '  }' \
  '}'
put "$EYES/$EYPKG/EyeExemptTwo.java" \
  'package io.github.cuukenn.encryptor.eye.filter;' \
  'import javax.servlet.AsyncContext;' \
  'class EyeExemptTwo { AsyncContext ac; }'
put "$EYES/$EYPKG/EyeUniform.java" \
  'package io.github.cuukenn.encryptor.eye.filter;' \
  'import javax.servlet.ServletOutputStream;' \
  'class EyeUniform { ServletOutputStream out; }'
# boot3 侧：按登记口径生成——两个豁免文件做"已知源码级改写"，其余机械替换。
mkdir -p "$EYEC/$EYPKG"
bash "$S" < "$EYES/$EYPKG/EyeUniform.java" > "$EYEC/$EYPKG/EyeUniform.java"
sed -e 's/javax\.servlet/jakarta.servlet/g' \
    -e 's/getStatusCode()/getStatusCode().value()/' \
    "$EYES/$EYPKG/EyeExemptOne.java" > "$EYEC/$EYPKG/EyeExemptOne.java"
bash "$S" < "$EYES/$EYPKG/EyeExemptTwo.java" > "$EYEC/$EYPKG/EyeExemptTwo.java"
EYE1="$EYPKG/EyeExemptOne.java"
EYE2="$EYPKG/EyeExemptTwo.java"

# 正例：豁免命中 → exit 0 语义不变，且产出 EYE-DIFF 眼审 diff + 汇总尾部 EXEMPT-FILES-INSPECT 标记。
run bash "$S" --diff "$EYES" "$EYEC" --expect-diff "$EYE1" --expect-diff "$EYE2"
assert_rc 0 "T7.1 豁免文件眼审输出不改变退出码（豁免命中仍 exit 0）"
assert_out_contains "EYE-DIFF: $EYE1" "T7.2 豁免文件 1 打印 EYE-DIFF 眼审 diff"
assert_out_contains "EXEMPT-FILES-INSPECT: 2 files printed above" "T7.3 汇总尾部打印 EXEMPT-FILES-INSPECT 标记（计数=豁免文件数）"

# 反例（反向渗入红例）：--exclude spring.factories 的复制对在 boot3 侧重新引入旧装配文件；
# 该文件同时被 exclude 名义豁免吞掉（copy 清单多余文件不另报 MISSING），必须由断言本身转红。
put "$EYEC/main/resources/META-INF/spring.factories" \
  'org.springframework.boot.autoconfigure.EnableAutoConfiguration=\' \
  'io.github.cuukenn.encryptor.eye.configuration.EyeConfiguration'
run bash "$S" --diff "$EYES" "$EYEC" --exclude spring.factories --expect-diff "$EYE1" --expect-diff "$EYE2"
assert_rc 1 "T7.4 boot3 侧重新引入 spring.factories → exit 1"
assert_out_contains "SPRING-FACTORIES-CREEP: boot3 copy reintroduced spring.factories: main/resources/META-INF/spring.factories" "T7.5 SPRING-FACTORIES-CREEP 行定位渗入文件"

# 正例（当前口径回归）：boot3 复制模块已删除 spring.factories（红例文件移除）→ 复制对重回全量 PASS。
rm -f "$EYEC/main/resources/META-INF/spring.factories"
rmdir "$(dirname "$EYEC/main/resources/META-INF/spring.factories")" 2>/dev/null || true
run bash "$S" --diff "$EYES" "$EYEC" --exclude spring.factories --expect-diff "$EYE1" --expect-diff "$EYE2"
assert_rc 0 "T7.6 boot3 侧已删 spring.factories 的存活复制对 → exit 0（反向断言不出假红）"

# ------------------------------------------------------------
echo
echo "== 自测汇总: PASS=$PASS FAIL=$FAIL =="
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
