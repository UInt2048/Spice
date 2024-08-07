SHELL            = /bin/sh

TARGET_GUI       = Spice
TARGET_CLI       = spice
PACKAGE          = lol.spyware.spicy
VERSION          = 1.0.0

BIN              = bin
RES              = res
APP              = $(BIN)/Payload/$(TARGET_GUI).app
SRC_ALL          = src/shared
SRC_CLI          = src/untether
SRC_GUI          = src/app
SRC_PWN          = src/exploit

PAYLOAD          = $(SRC_CLI)/generated/lol.spyware.spiceuntether_1.0.160_iphoneos-arm.deb
NO_UNTETHER     := $(SRC_CLI)/stage3.m $(SRC_CLI)/stage4.m $(SRC_CLI)/generator.m # These are only pre-dependencies
UNTETHER_SRC    := $(filter-out $(NO_UNTETHER),$(wildcard $(SRC_CLI)/*.m))
FORMAT_SRC      := $(filter-out $(SRC_ALL)/offsets.m,$(wildcard $(SRC_ALL)/*.h $(SRC_ALL)/*.m $(SRC_CLI)/*.h $(SRC_CLI)/*.m $(SRC_CLI)/*.c $(SRC_GUI)/*.h $(SRC_GUI)/*.m $(SRC_PWN)/*.h $(SRC_PWN)/*.m))
JAKE             = submodules/libjake
ifdef RELEASE
IPA              = $(TARGET_GUI).ipa
else
IPA              = $(TARGET_GUI)-DEV.ipa
endif
UNTETHER         = lib$(TARGET_CLI).dylib
TRAMP            = trampoline
ICONS           := $(wildcard $(RES)/Icon-*.png)
FILES           := $(TARGET_GUI) Info.plist Base.lproj/LaunchScreen.storyboardc $(ICONS:$(RES)/%=%) Unrestrict.dylib bootstrap.deb jailbreak-resources.deb mobilesubstrate.deb

SDK_FILE        := src/untether/sdk.txt
SDK_RESULT      := $(shell cat ${SDK_FILE})
ARCH_FILE       := src/untether/arch.txt
ARCH_RESULT     := $(shell cat ${ARCH_FILE})

IGCC            ?= $(SDK_RESULT) clang -mios-version-min=10.0
ARCH_GUI        ?= -arch $(ARCH_RESULT)
ARCH_CLI        ?= -arch $(ARCH_RESULT)
IGCC_FLAGS      ?= -Wall -Wformat=0 -flto -Isrc -Iinclude -larchive -fmodules -framework IOKit $(CFLAGS)
ifdef LEGACYSDK
IGCC_FLAGS      += -Wl,-U,_SecKeyCreateWithData,-U,_SecKeyVerifySignature,-U,_fs_snapshot_list,-U,_fs_snapshot_rename
endif
ifdef RELEASE
IGCC_FLAGS      += -DRELEASE=1
endif
ifdef FD
STAGE_2_FLAGS    = -DDYLD_CACHE_FD=$(FD)
CONTROL_FOLDER   = $(SRC_CLI)/debian/fd$(FD)
else
STAGE_2_FLAGS    = -DSTAGE1FD_SCREAM_TEST=1
CONTROL_FOLDER   = $(SRC_CLI)/debian/fdscream
endif
UNTETHER_FLAGS  ?= -I$(JAKE)/src -I$(JAKE)/img4lib/libvfs -L$(JAKE) -ljake -L$(JAKE)/img4lib -limg4 -L$(JAKE)/img4lib/lzfse/build/bin -llzfse
IBTOOL          ?= $(SDK_RESULT) ibtool
IBTOOL_FLAGS    ?= --output-format human-readable-text --errors --warnings --notices --target-device iphone --target-device ipad $(IBFLAGS)
SIGN            ?= codesign
SIGN_FLAGS      ?= -s -

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

$(APP)/bootstrap.deb:
	echo Copying file to $@
	cp $(RES)/spicebootstrap_1.0_iphoneos-arm.deb $@

$(APP)/jailbreak-resources.deb:
	echo Copying file to $@
	cp $(RES)/jailbreak-resources.deb $@
	
$(APP)/mobilesubstrate.deb:
	echo Copying file to $@
	cp $(RES)/mobilesubstrate_0.9.7113_iphoneos-arm.deb $@

# TODO: Make more accurate prerequisites

$(SRC_ALL)/offsets.h:
$(SRC_CLI)/control:
$(SRC_CLI)/postinst:
$(SRC_CLI)/compile_stage2.sh:
$(SRC_CLI)/compile_stage3.sh:
$(SRC_CLI)/compile_stage4.sh:

$(SRC_CLI)/generated/stage2_hash3.h: $(SRC_CLI)/stage3.m $(SRC_CLI)/compile_stage3.sh
	bash $(SRC_CLI)/compile_stage3.sh

$(SRC_CLI)/generated/stage2_hash4.h: $(SRC_CLI)/stage4.m $(SRC_ALL)/*.m $(SRC_ALL)/*.c $(SRC_PWN)/*.m $(SRC_CLI)/generated/stage2_hash3.h $(SRC_CLI)/compile_stage4.sh $(JAKE)/libjake.a
	bash $(SRC_CLI)/compile_stage4.sh

$(SRC_CLI)/install.m: $(SRC_ALL)/offsets.h $(SRC_CLI)/generated/stage2_hash3.h $(SRC_CLI)/generated/install_stage3_offsets.h

$(SRC_CLI)/stage2.m: $(SRC_ALL)/*.m $(SRC_ALL)/*.c $(SRC_CLI)/install.m $(SRC_CLI)/stage1.m $(SRC_CLI)/generated/stage2_hash3.h $(SRC_CLI)/generated/stage2_hash4.h $(SRC_CLI)/stage2.entitlements $(SRC_CLI)/compile_stage2.sh
	bash $(SRC_CLI)/compile_stage2.sh $(STAGE_2_FLAGS)

$(PAYLOAD): $(UNTETHER_SRC) $(SRC_ALL)/*.m $(SRC_ALL)/*.c $(SRC_CLI)/*.sh $(SRC_CLI)/generated/stage2_hash3.h $(SRC_CLI)/generated/stage2_hash4.h $(SRC_CLI)/stage2.m $(SRC_CLI)/control $(SRC_CLI)/postinst
	rm -rf -- $(SRC_CLI)/generated/package && rm -f $(SRC_CLI)/generated/*.deb
	mkdir -p $(SRC_CLI)/generated/package/DEBIAN && cp $(CONTROL_FOLDER)/control $(SRC_CLI)/generated/package/DEBIAN/control && cp $(SRC_CLI)/debian/postinst $(SRC_CLI)/generated/package/DEBIAN/postinst
	mkdir -p $(SRC_CLI)/generated/package/private/etc/racoon && cp $(SRC_CLI)/generated/install_stage1_2 $(SRC_CLI)/generated/package/private/etc/racoon/install_stage1_2
	mkdir -p $(SRC_CLI)/generated/package/usr/sbin && cp $(SRC_CLI)/generated/racoon.dylib $(SRC_CLI)/generated/package/usr/sbin/racoon.dylib
	mkdir -p $(SRC_CLI)/generated/package/spice && cp $(SRC_CLI)/generated/stage4 $(SRC_CLI)/generated/package/spice/stage4
	find . -name ".DS_Store" -delete && dpkg-deb -b $(SRC_CLI)/generated/package && dpkg-name $(SRC_CLI)/generated/package.deb

$(APP)/$(TARGET_GUI): $(SRC_GUI)/*.m $(SRC_ALL)/*.m $(SRC_ALL)/*.c $(SRC_PWN)/*.m $(JAKE)/libjake.a $(SRC_CLI)/uland_offsetfinder.m | $(APP)
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

$(UNTETHER): $(UNTETHER_SRC) $(SRC_ALL)/*.m $(SRC_ALL)/*.c $(SRC_PWN)/*.m $(JAKE)/libjake.a | $(SRC_ALL)/offsets.h $(PAYLOAD)
	$(IGCC) $(ARCH_CLI) $(UNTETHER_FLAGS) -shared -o $@ -Wl,-exported_symbols_list,res/untether.txt $(IGCC_FLAGS) $(STAGE_2_FLAGS) $^
	$(SIGN) $(SIGN_FLAGS) $@

$(TRAMP):
	$(IGCC) $(ARCH_CLI) -o $@ -L. -l$(TARGET_CLI) -Wl,-exported_symbols_list,res/tramp.txt $(IGCC_FLAGS) -xc <<<''
	$(SIGN) $(SIGN_FLAGS) $@

$(JAKE)/libjake.a: $(JAKE)/Makefile
	$(MAKE) $(AM_MAKEFLAGS) -C $(JAKE) all CC='$(IGCC) $(ARCH_CLI)' LD='$(IGCC) $(ARCH_CLI)' COMMONCRYPTO=1

$(JAKE)/Makefile:
	git submodule update --init --recursive
	$(MAKE) $(AM_MAKEFLAGS) -C $(JAKE)/img4lib/lzfse all CC='$(IGCC) $(ARCH_CLI)' LD='$(IGCC) $(ARCH_CLI)'

clean:
	rm -rf $(BIN)
	rm -rf $(SRC_CLI)/generated/*
	rm -f *.ipa *.dylib $(TRAMP)
	$(MAKE) $(AM_MAKEFLAGS) -C $(JAKE) clean CC='$(IGCC) $(ARCH_CLI)'
	clang-format -i -style="{BasedOnStyle: WebKit, InsertNewlineAtEOF: true, UseTab: Never}" $(FORMAT_SRC)
	clang-format -i -style="{BasedOnStyle: WebKit, InsertNewlineAtEOF: true, UseTab: Never, AlignConsecutiveAssignments: AcrossEmptyLinesAndComments}" $(SRC_ALL)/offsets.m

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
