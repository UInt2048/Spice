#!/bin/bash

# Makefile for stage 3 as the Makefile in the root dir is outdated (because I suck at Makefiles)
cd $(realpath "$(dirname "${BASH_SOURCE[0]}")") # Ensure we're in the script directory
$(< ./sdk.txt) clang -static -nostdlib -fno-stack-protector -e _where_it_all_starts -mios-version-min=10.0 -arch "$(< ./arch.txt)" stage3.c -o stage3.a && jtool --sign --inplace stage3.a && jtool --sig stage3.a

# We should sign stage 3 without a legacy SHA1 code directory
# The hash we want is the first 20 bytes of the SHA256 CDHash
# See https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes

echo -e -n "// Generated file by compile_stage3.sh, do not edit\n#ifndef STAGE2_HASH3\n#define STAGE2_HASH3 {0x" > ./stage2_hash3.h
echo -e -n $(codesign --display -vvv ./stage3.a &> ./stage3hashtemp.txt && grep "CDHash=" stage3hashtemp.txt | sed 's/CDHash=//; s/../&,0x/g; s/,0x$//' && rm ./stage3hashtemp.txt) >> ./stage2_hash3.h
(echo -e "}\n#endif") >> ./stage2_hash3.h

# Prove that worked
cat ./stage2_hash3.h