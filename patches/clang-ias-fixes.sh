#!/bin/bash
# LLVM integrated-assembler compatibility fixes for pre-4.16 arm64 kernels.
#
# Why: GNU as accepts arrangement-index syntax like 'v0.4s[0]', while LLVM's
# integrated assembler only accepts the element-size form 'v0.s[0]'.  This
# kernel tree hardcodes 'CLANG_FLAGS += -no-integrated-as' (LLVM bug 30792
# workaround), which makes clang hand every C file to the AOSP GCC 4.9
# binutils (< 2.35).  Those reject clang 15's '.file 0 "..."' lines with
# "junk at end of line / file number less than one" (see KCFLAGS override in
# config.env).  With the integrated assembler restored, clang 15 then fails
# on arrangement-index operands, e.g. arch/arm64/crypto/aes-ce-cipher-core.c:
#   "umov %w[out], v0.4s[0]"  ->  "invalid operand for instruction"
# (ClangBuiltLinux issue #1392, fixed upstream in v4.16 by commit
# 019cd46984d0).  Rewriting vN.xx[K] -> vN.x[K] across every arm64 .c/.S
# source is semantics-preserving (the element-size specifier is the ARM
# canonical form and is accepted by both assemblers).
set -euo pipefail

KERNEL_DIR=${KERNEL_DIR:?KERNEL_DIR must be set}
cd "$KERNEL_DIR"

files=$(find arch/arm64 -type f \( -name '*.c' -o -name '*.S' \) | wc -l)

find arch/arm64 -type f \( -name '*.c' -o -name '*.S' \) -print0 | \
  xargs -0 sed -i -E \
    -e 's/v([0-9]+)\.16b\[/v\1.b[/g' \
    -e 's/v([0-9]+)\.8b\[/v\1.b[/g' \
    -e 's/v([0-9]+)\.8h\[/v\1.h[/g' \
    -e 's/v([0-9]+)\.4h\[/v\1.h[/g' \
    -e 's/v([0-9]+)\.4s\[/v\1.s[/g' \
    -e 's/v([0-9]+)\.2s\[/v\1.s[/g' \
    -e 's/v([0-9]+)\.2d\[/v\1.d[/g'

echo "LLVM IAS element-access fixes applied across ${files} arm64 sources"
