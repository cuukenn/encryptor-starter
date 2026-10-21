#!/usr/bin/env bash
#
# javax-to-jakarta.sh — 机械包名替换（javax.servlet → jakarta.servlet）
#                      与复制对（-boot3 模块 vs javax 对位）逐字节 diff 守卫。
#
# 设计定位（boot3 双线，Task 4/5/6 复用）：
#   1) stdin 模式：javax 源文件 → jakarta 源文件，作为复制器直用的管道。
#   2) --diff 模式：对 base 目录逐文件做同样的机械替换，与 copied 目录逐字节比对；
#      漂移输出必须定位到具体文件（便于人审），exit code 供 CI 判定。
#   3) --expect-diff：gateway 型复制对里"非纯机械"的 Spring API 改写文件
#      （如 getMethodValue 移除、getStatusCode 返回类型变更）登记为 diff-inspected：
#      豁免逐字节比对，但强制双侧文件存在、登记 pattern 必须真实命中；
#      其余未豁免文件仍要求逐字节一致。
#      web/starter 型纯机械对不带任何 --expect-diff 即可全量 PASS。
#   注意：白名单只有一条——javax.servlet → jakarta.servlet；任何其他差异（pom、
#   装配注解、Spring API）只能通过 --exclude / --expect-diff 显式登记，不得黑箱扩白。
#   协议逻辑（JWE/AAD/防重放）不进复制对、也不允许经此脚本豁免式漂移。
#
# 用法：
#   scripts/javax-to-jakarta.sh                                    # stdin → stdout
#   scripts/javax-to-jakarta.sh --diff <base-dir> <copied-dir> [options]
#   scripts/javax-to-jakarta.sh --help
#
# --diff 选项（均可重复）：
#   --exclude <pattern>      在默认排除之外追加排除（被排除文件不参与清单与逐字节比对）
#   --expect-diff <pattern>  登记已知源码级改写文件（diff-inspected）：
#                            仅校验双侧存在 + pattern 命中，不参与逐字节比对
#
# pattern 匹配规则（glob 语法生效：* 匹配任意子串，`.` 按字面匹配；两个分支同为严格匹配，非子串匹配）：
#   含 '/' → 相对路径严格后缀匹配（rel 以 pattern 结尾才算命中，如 web/filter/X.java）
#   不含 '/' → basename 匹配（如 pom.xml / .DS_Store 命中任意深度、任意目录；*.evict 类通配亦可用）
#
# 默认排除（预期差异，不计为漂移）：pom.xml（boot3 模块的 pom 结构差异）、.DS_Store（mac 噪音）——
# 均为 basename pattern，任意深度命中。追加排除的 glob 用法示例：--exclude 'logs/generated.*'；
# ⚠️ 模块根级（非 src 级）diff 会碰见 target/ 构建产物，建议追加以 --exclude 'target/*' 登记排除。
#
# 退出码：0 = 所有参与比对文件变换后逐字节一致（或全部属已登记豁免）；
#         1 = 发现漂移（DIFF / MISSING / EXEMPT-PATTERN-UNMATCHED 行定位到具体文件）；
#         2 = 用法错误 / IO 错误
#
# CI 参数：JX2J_DIFF_MAX_LINES（默认 40；单个漂移文件的 diff 展示上限；0 = 不截断）
#
# @author changgg
set -euo pipefail

PROG_NAME="javax-to-jakarta.sh"
MAX_DIFF_LINES="${JX2J_DIFF_MAX_LINES:-40}"

usage() {
  sed -n '/^# 用法：/,/^# 退出码：/p' "$0" | sed -e 's/^# \{1,2\}//'
}

die() {
  echo "$PROG_NAME: $*" >&2
  echo "$PROG_NAME: --help 查看用法" >&2
  exit 2
}

# 变换核心：唯一白名单替换（含子包；注释/字符串同口径替换；javax.crypto 等其他包不动）。
transform() {
  LC_ALL=C perl -pe 's/javax\.servlet/jakarta.servlet/g'
}

# pattern 是否命中相对路径（glob 语法生效，`*` 为任意子串；两分支均为严格匹配而非子串匹配）：
#   不含 '/' → basename 匹配（如 pom.xml 命中任意深度的同名文件）
#   含 '/'   → 相对路径严格后缀匹配（rel 以 pattern 结尾；也支持整串相等）
pattern_matches() {
  local pat="$1" rel="$2"
  if [ "${pat#*/}" = "$pat" ]; then
    case "${rel##*/}" in
      $pat) return 0 ;;
    esac
    return 1
  fi
  case "$rel" in
    */$pat) return 0 ;;
    $pat)   return 0 ;;
  esac
  return 1
}

# 排除判定：--exclude/default 排除均走 pattern 匹配（basename pattern → 任意深度命中；含 '/' pattern → 严格后缀命中）。
excluded() {
  local rel="$1"
  local pat
  for pat in "${EXCLUDES[@]}"; do
    if pattern_matches "$pat" "$rel"; then
      return 0
    fi
  done
  return 1
}

# ---------- 模式 1：stdin → stdout ----------
if [ $# -eq 0 ]; then
  transform
  exit 0
fi

mode="${1:-}"

if [ "$mode" = "--help" ] || [ "$mode" = "-h" ]; then
  usage
  exit 0
fi

if [ "$mode" != "--diff" ]; then
  echo "$PROG_NAME: 未识别的模式: $mode" >&2
  usage
  exit 2
fi
shift

if [ $# -lt 2 ]; then
  echo "$PROG_NAME: --diff 需要两个目录参数：<base-dir> <copied-dir>" >&2
  usage
  exit 2
fi

BASE_DIR="$1"
COPY_DIR="$2"
shift 2

EXCLUDES=("pom.xml" ".DS_Store")
EXEMPT_PATTERNS=()
EXEMPT_HITS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --exclude|-x)
      [ $# -ge 2 ] || die "--exclude 需要 pattern 参数"
      EXCLUDES+=("$2")
      shift 2
      ;;
    --expect-diff|-e)
      [ $# -ge 2 ] || die "--expect-diff 需要 pattern 参数"
      EXEMPT_PATTERNS+=("$2")
      EXEMPT_HITS+=(0)
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "$PROG_NAME: --diff 未识别选项: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [ $# -gt 0 ]; then
  echo "$PROG_NAME: 多余的参数: $*" >&2
  usage
  exit 2
fi

if [ ! -d "$BASE_DIR" ]; then
  die "base 目录不存在: $BASE_DIR"
fi
if [ ! -d "$COPY_DIR" ]; then
  die "copy 目录不存在: $COPY_DIR"
fi

if ! WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/jx2j-diff.XXXXXX")"; then
  die "无法创建临时工作目录（检查 TMPDIR=${TMPDIR:-/tmp} 是否可写）"
fi
trap 'rm -rf "$WORKDIR"' EXIT

# 文件清单（相对路径，C 顺序，保证输出确定性）。
(cd "$BASE_DIR" && find . -type f) | sed -e 's|^\./||' | LC_ALL=C sort -u > "$WORKDIR/base.list"
(cd "$COPY_DIR" && find . -type f) | sed -e 's|^\./||' | LC_ALL=C sort -u > "$WORKDIR/copy.list"

excl_summary="$(LC_ALL=C printf '%s\n' "${EXCLUDES[@]}" | LC_ALL=C sort -u | LC_ALL=C tr '\n' ' ')"
exempt_summary="(none)"
if [ "${#EXEMPT_PATTERNS[@]}" -gt 0 ]; then
  exempt_summary="$(LC_ALL=C printf '%s\n' "${EXEMPT_PATTERNS[@]}" | LC_ALL=C tr '\n' ' ')"
fi

echo "=== javax-to-jakarta diff 守卫 ==="
echo "base: $BASE_DIR"
echo "copy: $COPY_DIR"
echo "excludes(默认+参数): $excl_summary"
echo "expect-diff(登记豁免): $exempt_summary"

checked=0
uniform=0
exempt=0
differing=0
missing=0
rc_final=0

# 单文件比较：变换后 cmp；漂移则打印 DIFF 行定位（diff 展示受 MAX_DIFF_LINES 截断，0=全量）。
# 函数保证返回 0（计数器在调用侧累计，不依赖返回值，避免 set -e 中断 while read 循环）。
compare_one() {
  local rel="$1"
  local base_f="$BASE_DIR/$rel"
  local copy_f="$COPY_DIR/$rel"
  if ! transform < "$base_f" > "$WORKDIR/candidate.tmp"; then
    echo "TRANSFORM-ERROR: $rel"
    rc_final=1
    return 0
  fi
  if cmp -s "$WORKDIR/candidate.tmp" "$copy_f"; then
    uniform=$((uniform+1))
    return 0
  fi
  differing=$((differing+1))
  rc_final=1
  echo "DIFF: $rel"
  LC_ALL=C diff -u "$WORKDIR/candidate.tmp" "$copy_f" > "$WORKDIR/drift.diff" 2>&1 || true
  if [ "$MAX_DIFF_LINES" -gt 0 ]; then
    LC_ALL=C head -n "$MAX_DIFF_LINES" "$WORKDIR/drift.diff" || true
    local total_lines hidden_lines
    total_lines="$(LC_ALL=C wc -l < "$WORKDIR/drift.diff" | LC_ALL=C tr -d ' ')"
    hidden_lines=$((total_lines - MAX_DIFF_LINES))
    if [ "$hidden_lines" -gt 0 ]; then
      echo "...（diff 截断：仅展示前 $MAX_DIFF_LINES 行，未展示 $hidden_lines 行；复跑时设 JX2J_DIFF_MAX_LINES=$total_lines 即可看到全部 $total_lines 行）"
    fi
  else
    LC_ALL=C cat "$WORKDIR/drift.diff" || true
  fi
  return 0
}

# ---------- 1) base 清单：缺失/豁免/比对 ----------
while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  if excluded "$rel"; then
    continue
  fi
  if [ ! -f "$COPY_DIR/$rel" ]; then
    missing=$((missing+1))
    rc_final=1
    echo "MISSING IN COPY: $rel"
    continue
  fi
  ematch=""
  ei=0
  while [ "$ei" -lt "${#EXEMPT_PATTERNS[@]}" ]; do
    if pattern_matches "${EXEMPT_PATTERNS[$ei]}" "$rel"; then
      ematch="${EXEMPT_PATTERNS[$ei]}"
      EXEMPT_HITS[$ei]=$(( ${EXEMPT_HITS[$ei]} + 1 ))
      break
    fi
    ei=$((ei+1))
  done
  if [ -n "$ematch" ]; then
    exempt=$((exempt+1))
    echo "EXEMPT: ${rel}（diff-inspected 登记命中 → 人工核对）"
    continue
  fi
  checked=$((checked+1))
  compare_one "$rel"
done < "$WORKDIR/base.list"

# ---------- 2) copy 清单：多余文件（base 没有而 copy 有 → 漂移） ----------
while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  if excluded "$rel"; then
    continue
  fi
  if [ ! -f "$BASE_DIR/$rel" ]; then
    missing=$((missing+1))
    rc_final=1
    echo "MISSING IN BASE: $rel"
  fi
done < "$WORKDIR/copy.list"

# ---------- 3) --expect-diff 登记有效性：pattern 未命中任何文件 = 登记失真 → 漂移退出 ----------
ei=0
while [ "$ei" -lt "${#EXEMPT_PATTERNS[@]}" ]; do
  if [ "${EXEMPT_HITS[$ei]}" -eq 0 ]; then
    rc_final=1
    echo "EXEMPT-PATTERN-UNMATCHED: --expect-diff ${EXEMPT_PATTERNS[$ei]} 未命中任何文件（登记路径过期/拼错，请人审后修正登记）"
  fi
  ei=$((ei+1))
done

echo "=== 统计: checked=$checked uniform=$uniform exempt=$exempt differing=$differing missing=$missing ==="
if [ "$rc_final" -eq 0 ]; then
  echo "=== 结果: UNIFORM (exit 0) ==="
  exit 0
else
  echo "=== 结果: DRIFT (exit 1；按上方 DIFF / MISSING / EXEMPT-PATTERN-UNMATCHED 定位文件)" >&2
  exit 1
fi
