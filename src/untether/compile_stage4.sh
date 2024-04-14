#!/bin/bash

# Makefile for stage 4 as the Makefile in the root dir is outdated (because I suck at Makefiles)
cd $(realpath "$(dirname "${BASH_SOURCE[0]}")") # Ensure we're in the script directory
$(< ./sdk.txt) clang -mios-version-min=10.0 -arch "$(< ./arch.txt)" -I../../include -larchive -framework IOKit ../../submodules/libjake/img4lib/libimg4.a ../../submodules/libjake/libjake.a stage4.m uland_offsetfinder.m ../shared/*.m ../shared/realsym.c -framework Foundation -framework Security -I../ -I ../../submodules/libjake/src/ -I ../../submodules/libjake/img4lib/libvfs/ -L../../submodules/libjake/img4lib/ -L../../submodules/libjake/lib/ -o stage4 && jtool --sign --inplace stage4 && jtool --sig stage4

# We should sign stage 4 without a legacy SHA1 code directory
# The hash we want is the first 20 bytes of the SHA256 CDHash
# See https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes

echo -e -n "// Generated file by compile_stage4.sh, do not edit\n#ifndef STAGE2_HASH4\n#define STAGE2_HASH4 {0x" > ./stage2_hash4.h
echo -e -n $(codesign --display -vvv ./stage4 &> ./stage4hashtemp.txt && grep "CDHash=" stage4hashtemp.txt | sed 's/CDHash=//; s/../&,0x/g; s/,0x$//' && rm ./stage4hashtemp.txt) >> ./stage2_hash4.h
(echo -e "}\n#endif") >> ./stage2_hash4.h

# Prove that worked
cat ./stage2_hash4.h