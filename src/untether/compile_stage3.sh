#!/bin/bash

# Makefile for stage 3 as the Makefile in the root dir is outdated (because I suck at Makefiles)
cd $(realpath "$(dirname "${BASH_SOURCE[0]}")") # Ensure we're in the script directory
$(< ./sdk.txt) clang -shared -fno-stack-protector -fno-stack-check -fno-builtin -ffreestanding -mios-version-min=10.0 -arch "$(< ./arch.txt)" stage3.m -o ./generated/racoon.dylib && jtool --sign --inplace ./generated/racoon.dylib && jtool --sig ./generated/racoon.dylib

# We should sign stage 3 without a legacy SHA1 code directory
# The hash we want is the first 20 bytes of the SHA256 CDHash
# See https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes

echo -e -n "// Generated file by compile_stage3.sh, do not edit\n#ifndef STAGE2_HASH3\n#define STAGE2_HASH3 {0x" > ./generated/stage2_hash3.h
echo -e -n $(codesign --display -vvv ./generated/racoon.dylib 2>/dev/stdout | grep "CDHash=" | sed 's/CDHash=//; s/../&,0x/g; s/,0x$//') >> ./generated/stage2_hash3.h
(echo -e "}\n#endif") >> ./generated/stage2_hash3.h

# Prove that worked
cat ./generated/stage2_hash3.h

# Now we want to get our offsets that install.m needs
echo -e "// Generated file by compile_stage3.sh, do not edit\n#ifndef INSTALL_STAGE3_OFFSETS\n#define INSTALL_STAGE3_OFFSETS" > ./generated/install_stage3_offsets.h
echo $(nm ./generated/racoon.dylib | grep "_where_it_all_starts" | sed 's/[^0-9a-f].*$//g; s/^0*/#define STAGE3_JUMP 0x/g') >> ./generated/install_stage3_offsets.h
echo -e $(jtool --sig ./generated/racoon.dylib | grep "Blob at offset" | sed 's/ (/\\n#define STAGE3_CSBLOB_SIZE /; s/ by.*$/\\n#endif/; s/Blob.*: /#define STAGE3_CSBLOB /') >> ./generated/install_stage3_offsets.h

# Prove that worked
cat ./generated/install_stage3_offsets.h