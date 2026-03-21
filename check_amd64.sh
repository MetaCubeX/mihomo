#!/bin/sh
flags=$(grep '^flags\b' </proc/cpuinfo | head -n 1)
flags=" ${flags#*:} "

has_flags () {
  for flag; do
    case "$flags" in
      *" $flag "*) :;;
      *) return 1;;
    esac
  done
}

determine_level () {
  level=0
  has_flags lm cmov cx8 fpu fxsr mmx syscall sse2 || return 0
  level=1
  has_flags cx16 lahf_lm popcnt sse4_1 sse4_2 ssse3 || return 0
  level=2
  has_flags avx avx2 bmi1 bmi2 f16c fma abm movbe xsave || return 0
  level=3
  has_flags avx512f avx512bw avx512cd avx512dq avx512vl || return 0
  level=4
}

determine_level
echo "Your CPU supports amd64-v$level"
return $level