#!/usr/bin/env bash
# Produce the list of instructions a guest program actually executes natively
# (W7). Run inside the Linux dev container (mise-tasks/linux-dev.sh).
#
#   tools/insn-trace/insn-census.sh <program> <output-prefix>
#
# Writes:
#   <prefix>.trace      every executed address (in order)
#   <prefix>.insns      each distinct executed address with its disassembly
#   <prefix>.forms      distinct "mnemonic operands-shape" forms with counts
#   <prefix>.mnemonics  distinct mnemonics
set -euo pipefail
program="$1"
prefix="$2"
here="$(cd "$(dirname "$0")" && pwd)"
tracer="${TMPDIR:-/tmp}/insn-trace"
cc -O2 -Wall -o "$tracer" "$here/insn-trace.c"

"$tracer" "$prefix.trace" "$program" >/dev/null

# The first traced address is the entry point; the difference to e_entry is
# the load bias (non-zero for static-pie, which Linux places in the mmap area).
entry="$(readelf -h "$program" | awk '/Entry point/ { print $4 }')"
bias=$(( 0x$(head -n1 "$prefix.trace") - entry ))

objdump -d -M intel --no-show-raw-insn "$program" \
  | awk -F'\t' '/^ *[0-9a-f]+:\t/ { a=$1; gsub(/[ :]/, "", a); print a "\t" $2 }' \
  > "$prefix.objdump"

sort -u "$prefix.trace" \
  | while read -r a; do printf '%x\n' $(( 0x$a - bias )); done \
  > "$prefix.addrs"

awk -F'\t' 'NR==FNR { want[$1]=1; next } ($1 in want) { print $1 "\t" $2 }' \
  "$prefix.addrs" "$prefix.objdump" > "$prefix.insns"

# Operand shape: registers by width class, memory, immediate.
awk -F'\t' '{
  insn=$2; sub(/ *#.*/, "", insn); sub(/ *<.*>/, "", insn)
  n=split(insn, parts, /[ ]+/); m=parts[1]; ops=""
  if (m ~ /^(rep|repz|repnz|lock|bnd|notrack|data16)$/) { m=m " " parts[2]; start=3 } else { start=2 }
  rest=""; for (i=start;i<=n;i++) rest=rest (rest==""?"":" ") parts[i]
  k=split(rest, o, /,/)
  for (i=1;i<=k;i++) {
    x=o[i]
    if (x ~ /PTR|\[/) { w=x; sub(/ PTR.*/, "", w); if (w ~ /\[/) w="m"; s="m:" tolower(w) }
    else if (x ~ /^(0x[0-9a-f]+|[0-9]+)$/) s="imm"
    else if (x ~ /^xmm/) s="xmm"
    else if (x ~ /^r(ax|bx|cx|dx|si|di|bp|sp|[0-9]+)$/) s="r64"
    else if (x ~ /^(e(ax|bx|cx|dx|si|di|bp|sp)|r[0-9]+d)$/) s="r32"
    else if (x ~ /^((ax|bx|cx|dx|si|di|bp|sp)|r[0-9]+w)$/) s="r16"
    else if (x ~ /^((al|bl|cl|dl|ah|bh|ch|dh|sil|dil|bpl|spl)|r[0-9]+b)$/) s="r8"
    else if (x ~ /^[fg]s:/) s="m:seg"
    else if (x ~ /^[0-9a-f]+$/) s="rel"
    else s=x
    ops=ops (ops==""?"":", ") s
  }
  print m (ops==""?"":" " ops)
}' "$prefix.insns" | sort | uniq -c | sort -k2 > "$prefix.forms"

awk '{ print $2 }' "$prefix.forms" | sort -u > "$prefix.mnemonics"
echo "$(wc -l < "$prefix.trace") steps, $(wc -l < "$prefix.addrs") distinct addresses, $(wc -l < "$prefix.forms") forms, $(wc -l < "$prefix.mnemonics") mnemonics" >&2

# Raw bytes of every executed instruction (input for the decoder comparison).
objdump -d -w -M intel "$program" \
  | awk -F'\t' 'NR==FNR { want[$1]=1; next }
      /^ *[0-9a-f]+:\t/ { a=$1; gsub(/[ :]/, "", a); if (a in want) { b=$2; sub(/ +$/, "", b); print b "\t" $3 } }' \
    "$prefix.addrs" - > "$prefix.raw"
