SHELL            = /bin/bash

TARGET_GUI       = Spice
TARGET_CLI       = spice
PACKAGE          = lol.spyware.spicy
VERSION          = 1.0.168

BIN              = bin
RES              = res
APP              = $(BIN)/Payload/$(TARGET_GUI).app
SRC_ALL          = src/shared
SRC_CLI          = src/untether
SRC_GUI          = src/app
JAKE             = submodules/libjake

PAYLOAD          = $(SRC_CLI)/generated/lol.spyware.spiceuntether_$(VERSION)_iphoneos-arm.deb
NO_UNTETHER     := $(SRC_CLI)/stage3.m $(SRC_CLI)/stage4.m $(SRC_CLI)/generator.m # These are only pre-dependencies
UNTETHER_SRC    := $(filter-out $(NO_UNTETHER),$(wildcard $(SRC_CLI)/*.m))

SDK_RESULT       = xcrun -sdk iphoneos11.4
ARCH_RESULT      = arm64

ifdef RELEASE
IPA              = $(TARGET_GUI)-$(ARCH_RESULT)-$(VERSION).ipa
else
IPA              = $(TARGET_GUI)-$(ARCH_RESULT)-$(VERSION)-DEV.ipa
endif
UNTETHER         = lib$(TARGET_CLI).dylib
TRAMP            = trampoline
ICONS           := $(wildcard $(RES)/Icon-*.png)
FILES           := $(TARGET_GUI) Info.plist Base.lproj/LaunchScreen.storyboardc $(ICONS:$(RES)/%=%) Unrestrict.dylib bootstrap.tar.lzma jailbreak-resources.deb uicache

IGCC            ?= $(SDK_RESULT) clang -mios-version-min=10.0
ARCH_GUI        ?= -arch $(ARCH_RESULT)
ARCH_CLI        ?= -arch $(ARCH_RESULT)
IGCC_FLAGS      ?= -Wall -Wformat=0 -flto -Isrc -Iinclude -larchive -fmodules -framework IOKit $(CFLAGS)
ifdef RELEASE
IGCC_FLAGS      += -DRELEASE=1
endif
STAGE_2_FLAGS    =
UNTETHER_FLAGS  ?= -I$(JAKE)/src -I$(JAKE)/img4lib/libvfs -L$(JAKE) -ljake -L$(JAKE)/img4lib -limg4 -L$(JAKE)/img4lib/lzfse/build/bin -llzfse
IBTOOL          ?= $(SDK_RESULT) ibtool
IBTOOL_FLAGS    ?= --output-format human-readable-text --errors --warnings --notices --target-device iphone --target-device ipad $(IBFLAGS)
SIGN            ?= codesign
SIGN_FLAGS      ?= -s -
JAKE_FLAGS      ?= -DUSE_COMMONCRYPTO=1 -DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8 -I$(JAKE)/img4lib/

.PHONY: all app ipa untether clean install payload

all: $(IPA) $(UNTETHER) $(TRAMP)

app: ipa

ipa: $(IPA)

untether: $(UNTETHER) $(TRAMP)

payload: $(PAYLOAD)

$(IPA): $(addprefix $(APP)/, $(FILES))
	cd $(BIN) && zip -x .DS_Store -qr9 ../$@ Payload

# TODO: make this less shit
$(APP)/Unrestrict.dylib:
	echo Copying file to $@
	cp $(RES)/Unrestrict.dylib $@

$(APP)/bootstrap.tar.lzma:
	echo Copying file to $@
	cp $(RES)/bootstrap.tar.lzma $@

$(APP)/jailbreak-resources.deb:
	echo Copying file to $@
	cp $(RES)/jailbreak-resources.deb $@

$(APP)/uicache:
	echo Copying file to $@
	cp $(RES)/uicache $@

# TODO: Make more accurate prerequisites

$(SRC_ALL)/offsets.h:
$(SRC_CLI)/debian/control:
$(SRC_CLI)/debian/postinst:
$(SRC_CLI)/generate_stage3.sh:
$(SRC_CLI)/generate_stage4.sh:

$(SRC_CLI)/generated/stage2_hash3.h: $(SRC_CLI)/stage3.m $(SRC_CLI)/generate_stage3.sh
	$(IGCC) $(ARCH_CLI) -shared -fno-stack-protector -fno-stack-check -fno-builtin -ffreestanding $(SRC_CLI)/stage3.m -o ./generated/racoon.dylib && \
	    jtool --sign --inplace ./generated/racoon.dylib && jtool --sig ./generated/racoon.dylib
	bash $(SRC_CLI)/generate_stage3.sh

$(SRC_CLI)/generated/stage2_hash4.h: $(SRC_CLI)/stage4.m $(SRC_ALL)/*.m $(SRC_ALL)/*.c $(SRC_CLI)/generated/stage2_hash3.h $(SRC_CLI)/generate_stage4.sh $(JAKE)/libjake.a
	$(IGCC) $(ARCH_CLI) -I src/ -I include/ -I $(JAKE)/src/ -I $(JAKE)/img4lib/libvfs/ \
	    -larchive -framework IOKit -framework UIKit -framework Foundation -framework Security \
	    $(JAKE)/img4lib/libimg4.a $(JAKE)/libjake.a $(SRC_CLI)/stage4.m $(SRC_CLI)/uland_offsetfinder.m $(SRC_ALL)/*.m $(SRC_ALL)/realsym.c \
	    -L$(JAKE)/img4lib/ -L$(JAKE)/img4lib/lzfse/build/bin -o ./generated/stage4 && \
	    jtool --sign --inplace ./generated/stage4 && jtool --sig ./generated/stage4
	bash $(SRC_CLI)/generate_stage4.sh

$(SRC_CLI)/install.m: $(SRC_ALL)/offsets.h $(SRC_CLI)/generated/stage2_hash3.h $(SRC_CLI)/generated/install_stage3_offsets.h

$(SRC_CLI)/stage2.m: $(SRC_ALL)/*.c $(SRC_CLI)/install.m $(SRC_CLI)/stage1.m $(SRC_CLI)/generated/stage2_hash3.h $(SRC_CLI)/generated/stage2_hash4.h $(SRC_CLI)/stage2.entitlements $(JAKE)/libjake.a
	$(IGCC) $(ARCH_CLI) -DUSE_COMMONCRYPTO=1 -I$(JAKE)/img4lib/ -I$(JAKE)/img4lib/lzfse/src/ -c $(JAKE)/img4lib/lzss.c -o $(JAKE)/img4lib/lzss.o
	$(IGCC) $(ARCH_CLI) $(JAKE_FLAGS) -I$(JAKE)/img4lib/lzfse/src/ -c $(JAKE)/img4lib/libvfs/vfs_enc.c -o $(JAKE)/img4lib/libvfs/vfs_enc.o
	$(IGCC) $(ARCH_CLI) $(JAKE_FLAGS) -I$(JAKE)/img4lib/lzfse/src/ -c $(JAKE)/img4lib/libvfs/vfs_file.c -o $(JAKE)/img4lib/libvfs/vfs_file.o
	$(IGCC) $(ARCH_CLI) $(JAKE_FLAGS) -I$(JAKE)/img4lib/lzfse/src/ -c $(JAKE)/img4lib/libvfs/vfs_img4.c -o $(JAKE)/img4lib/libvfs/vfs_img4.o
	$(IGCC) $(ARCH_CLI) $(JAKE_FLAGS) -I$(JAKE)/img4lib/lzfse/src/ -c $(JAKE)/img4lib/libvfs/vfs_lzfse.c -o $(JAKE)/img4lib/libvfs/vfs_lzfse.o
	$(IGCC) $(ARCH_CLI) $(JAKE_FLAGS) -I$(JAKE)/img4lib/lzfse/src/ -c $(JAKE)/img4lib/libvfs/vfs_lzss.c -o $(JAKE)/img4lib/libvfs/vfs_lzss.o
	$(IGCC) $(ARCH_CLI) $(JAKE_FLAGS) -I$(JAKE)/img4lib/lzfse/src/ -c $(JAKE)/img4lib/libvfs/vfs_mem.c -o $(JAKE)/img4lib/libvfs/vfs_mem.o
	$(IGCC) $(ARCH_CLI) $(JAKE_FLAGS) -I$(JAKE)/img4lib/lzfse/src/ -c $(JAKE)/img4lib/libvfs/vfs_sub.c -o $(JAKE)/img4lib/libvfs/vfs_sub.o
	$(IGCC) $(ARCH_CLI) $(JAKE_FLAGS) -I$(JAKE)/img4lib/libDER/ -c $(JAKE)/img4lib/libDER/DER_Encode.c -o $(JAKE)/img4lib/libDER/DER_Encode.o
	$(IGCC) $(ARCH_CLI) $(JAKE_FLAGS) -I$(JAKE)/img4lib/libDER/ -c $(JAKE)/img4lib/libDER/DER_Decode.c -o $(JAKE)/img4lib/libDER/DER_Decode.o
	$(IGCC) $(ARCH_CLI) $(JAKE_FLAGS) -I$(JAKE)/img4lib/libDER/ -c $(JAKE)/img4lib/libDER/oids.c -o $(JAKE)/img4lib/libDER/oids.o
	libtool -o $(JAKE)/img4lib/libimg4.a $(JAKE)/img4lib/lzss.o $(JAKE)/img4lib/libvfs/*.o $(JAKE)/img4lib/libDER/*.o
	$(IGCC) $(ARCH_CLI) $(JAKE)/img4lib/libimg4.a $(JAKE)/libjake.a $(SRC_ALL)/realsym.c $(SRC_ALL)/offsets.m \
	    $(SRC_CLI)/generator.m $(SRC_CLI)/install.m $(SRC_CLI)/stage1.m $(SRC_CLI)/racoon_www.m $(SRC_CLI)/uland_offsetfinder.m $(SRC_CLI)/a64.c $(SRC_CLI)/stage2.m $(STAGE_2_FLAGS) \
	    -I src/ -I $(JAKE)/src/ -I $(JAKE)/img4lib/libvfs/ -o ./generated/install_stage1_2 -framework Security -framework IOKit -framework UIKit -framework CoreFoundation -framework Foundation \
	    -L$(JAKE)/img4lib/ -L$(JAKE)/lib/ && ldid -S$(SRC_CLI)/stage2.entitlements ./generated/install_stage1_2

$(PAYLOAD): $(UNTETHER_SRC) $(SRC_ALL)/*.m $(SRC_ALL)/*.c $(SRC_CLI)/*.sh $(SRC_CLI)/generated/stage2_hash3.h $(SRC_CLI)/generated/stage2_hash4.h $(SRC_CLI)/stage2.m $(SRC_CLI)/debian/control $(SRC_CLI)/debian/postinst
	rm -rf -- $(SRC_CLI)/generated/package && rm -f $(SRC_CLI)/generated/*.deb
	mkdir -p $(SRC_CLI)/generated/package/DEBIAN && cp $(SRC_CLI)/debian/postinst $(SRC_CLI)/generated/package/DEBIAN/postinst
	sed 's/$$(VERSION)/$(VERSION)/g' $(SRC_CLI)/debian/control > $(SRC_CLI)/generated/package/DEBIAN/control
	mkdir -p $(SRC_CLI)/generated/package/private/etc/racoon && cp $(SRC_CLI)/generated/install_stage1_2 $(SRC_CLI)/generated/package/private/etc/racoon/install_stage1_2
	mkdir -p $(SRC_CLI)/generated/package/usr/sbin && cp $(SRC_CLI)/generated/racoon.dylib $(SRC_CLI)/generated/package/usr/sbin/racoon.dylib
	mkdir -p $(SRC_CLI)/generated/package/mystuff && cp $(SRC_CLI)/generated/stage4 $(SRC_CLI)/generated/package/mystuff/stage4
	find . -name ".DS_Store" -delete && dpkg-deb -b $(SRC_CLI)/generated/package && dpkg-name $(SRC_CLI)/generated/package.deb

$(APP)/$(TARGET_GUI): $(SRC_GUI)/*.m $(SRC_ALL)/*.m $(SRC_ALL)/*.c $(JAKE)/libjake.a $(SRC_CLI)/uland_offsetfinder.m | $(APP)
	$(IGCC) $(ARCH_GUI) $(UNTETHER_FLAGS) -o $@ -Wl,-exported_symbols_list,res/app.txt $(IGCC_FLAGS) $^

$(APP)/Info.plist: $(RES)/Info.plist | $(APP)
	sed 's/$$(TARGET)/$(TARGET_GUI)/g;s/$$(PACKAGE)/$(PACKAGE)/g;s/$$(VERSION)/$(VERSION)/g' $(RES)/Info.plist > $@

$(APP)/Icon-%.png: $(RES)/$(@F) | $(APP)
	cp $(RES)/$(@F) $@

$(APP)/Base.lproj/%.storyboardc: $(RES)/%.storyboard | $(APP)/Base.lproj
	$(IBTOOL) $(IBTOOL_FLAGS) --compilation-directory $(APP)/Base.lproj $<

$(APP):
	mkdir -p $@

$(APP)/Base.lproj:
	mkdir -p $@

$(UNTETHER): $(UNTETHER_SRC) $(SRC_ALL)/*.m $(SRC_ALL)/*.c $(JAKE)/libjake.a | $(SRC_ALL)/offsets.h $(PAYLOAD)
	$(IGCC) $(ARCH_CLI) $(UNTETHER_FLAGS) -shared -o $@ -Wl,-exported_symbols_list,res/untether.txt $(IGCC_FLAGS) $^
	$(SIGN) $(SIGN_FLAGS) $@

$(TRAMP):
	$(IGCC) $(ARCH_CLI) -o $@ -L. -l$(TARGET_CLI) -Wl,-exported_symbols_list,res/tramp.txt $(IGCC_FLAGS) -xc <<<''
	$(SIGN) $(SIGN_FLAGS) $@

$(JAKE)/libjake.a: $(JAKE)/Makefile
	$(MAKE) $(AM_MAKEFLAGS) -C $(JAKE) all CC='$(IGCC) $(ARCH_CLI)' LD='$(IGCC) $(ARCH_CLI)' COMMONCRYPTO=1 PLATFORM=ios

$(JAKE)/Makefile:
	git submodule update --init --recursive
	$(MAKE) $(AM_MAKEFLAGS) -C $(JAKE)/img4lib/lzfse all CC='$(IGCC) $(ARCH_CLI)' LD='$(IGCC) $(ARCH_CLI)'

clean:
	rm -rf $(BIN)
	rm -rf $(SRC_CLI)/generated/*
	rm -f *.ipa *.dylib $(TRAMP)
	$(MAKE) $(AM_MAKEFLAGS) -C $(JAKE) clean CC='$(IGCC) $(ARCH_CLI)'

ifndef ID
install:
	@echo 'Environment variable ID not set'
	exit 1
else
install: | $(IPA)
	cp res/*.mobileprovision $(APP)/embedded.mobileprovision
	echo '<?xml version="1.0" encoding="UTF-8"?>' >tmp.plist
	echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' >>tmp.plist
	echo '<plist version="1.0">' >>tmp.plist
	echo '<dict>' >>tmp.plist
	strings res/*.mobileprovision | egrep -A1 'application-identifier' >>tmp.plist
	strings res/*.mobileprovision | egrep -A1 'team-identifier' >>tmp.plist
	echo '</dict>' >>tmp.plist
	echo '</plist>' >>tmp.plist
	codesign -f -s '$(ID)' --entitlements tmp.plist $(APP)
	rm tmp.plist
	cd $(BIN) && zip -x .DS_Store -qr9 ../$(IPA) Payload
	ideviceinstaller -i $(IPA)
endif
