# Spice

## Basic overview
This was written by the @JakeBlair420 team (@s1guza, @stek29, @sparkey, @littlelailo)
There is a [presentation](https://media.ccc.de/v/36c3-11034-tales_of_old_untethering_ios_11) from @littlelailo he gave at 36C3 that gives a pretty good overview over the whole jailbreak including the bugs that were used and how we exploited them, so please watch this first before looking at the code base to get a good overview.
The bugs can be used to exploit this on all versions of iOS 11, in theory it's also possible to pop the i5 on some versions of iOS 10 with this, but the repo and spice only support 64 bit devices.
The jailbreak is in an incomplete state atm and only works on none SMAP devices (A7-A9) and with hardcoded symbols (but the offsetfinders are also nearly done).
We added comments as much as possible to explain what still doesn't work/needs more testing if someone wants to port this to other devices.
Xerub also reimplemented parts of this in acron and used a better technique for a faster write what where so you should definitly check out his implementation.

## Bugs

### Racoon write what where bug
In the beginning we need to get a write what where primitive in some userland process on start to kickstart the exploit chain. We also need to be able to do multiple writes.
For that we use a bug in racoons config parser that was already discovered by pod2g back in 2011.
Racoon is a vpn client that can be used to interact with an ipsec vpn server, but the only important feature we need for this jailbreak is it's config parser, which was written in yacc.
Racoon is part of the ipsec project which was hosted on ipsec-tools.sourceforge.net, but it has been abandoned since 2014. Apple still maintains their fork on https://opensource.apple.com/source/ipsec/
The configuration parser is implemented in https://opensource.apple.com/source/ipsec/ipsec-317.220.1/ipsec-tools/racoon/cfparse.y.auto.html 
Execution flow will start in main.c where we will setup the lcconf struct and point the config file path to /etc/racoon/racoon.conf.
You can specifiy your own config with the -f argument which helps a lot when debugging (cause you don't have to replace the racoon.conf each time you test sth)
The bug is in the statment for parsing addrwinslists (lists of ipv4 addresses):
```C
addrwinslist // defines what an addrwinslist has to consit of
	:	addrwins // either just one addrwins statment
	|	addrwins COMMA addrwinslist // of an addrwins statment followed by a comma followed by another addrwinslist (so you can have multiple addrwins statments)
	;
addrwins // this then defines what an addrwins statment has to consit of
	:	ADDRSTRING // so it has to consist of an ADDRSTRING which is just a regex matching an ipv4 address (defined in cftoken.l) [[a-fA-F0-9:]([a-fA-F0-9:\.]*|[a-fA-F0-9:\.]*%[a-zA-Z0-9]*)]
		{ // as soon as the parser will find this statment it will run the code below (ENABLE_HYBRID is defined)
#ifdef ENABLE_HYBRID
			struct isakmp_cfg_config *icc = &isakmp_cfg_config; // this will get a pointer to a global struct

			if (icc->nbns4_index > MAXWINS) { // then it will perform a bounds check. This is the bug because it's an off by one (should be >= instead of >, because they define nbns4 as an array of size MAXWINS)
				racoon_yyerror("No more than %d WINS", MAXWINS);
                return -1;
            }
			if (inet_pton(AF_INET, $1->v, // $1->v is the parsed ip address
			    &icc->nbns4[icc->nbns4_index++]) != 1) // this call will then parse the ip address string into an uint32_t and then post increment the index
				racoon_yyerror("bad IPv4 WINS address.");

			vfree($1);
#else
			racoon_yyerror("racoon not configured with --enable-hybrid");
#endif
		}
	;
```
The global struct looks like this (defined under https://opensource.apple.com/source/ipsec/ipsec-317.220.1/ipsec-tools/racoon/isakmp_cfg.h.auto.html):
```
struct isakmp_cfg_config {
	in_addr_t		network4;
	in_addr_t		netmask4;
	in_addr_t		dns4[MAXNS];
	int			dns4_index;
	in_addr_t		nbns4[MAXWINS]; // MAXWINS is defined as 4
	int			nbns4_index; // note that this is an int so it could contain negativ values
	[...]
};
```
This means that we can use this to trigger a relativ out of bounds write with the following syntax (and then turn it into an absolut one):
```
mode_cfg {
	wins4 1.1.1.1; // increment the nbns4_index by one [0 => 1]
	wins4 1.1.1.1; // increment the nbns4_index by one [1 => 2]
	wins4 1.1.1.1; // increment the nbns4_index by one [2 => 3]
	wins4 1.1.1.1; // increment the nbns4_index by one [3 => 4] (now it is pointing out of bounds/pointing to our own nbns4_index value)
	wins4 255.255.255.255; // this will get converted into the uint32_t 0xffffffff => -1 if you convert it to an int so the nbns4_index will now have the value -1 and with that pointing to the dns4_index
	wins4 50.253.255.255; // this will now overwrite the dns4_array index with -718 and increment the nbns4_index by 1 again so it's 0 again now and we can repeat this as often times as we want
	dns4 255.255.255.255; // now we can use the dns4 statments here to smash a pointer in the globals (lcconf ptr)
	dns4 255.255.255.255; // smash upper half (as the dns4 array index will also get incremented every time)
}
timer { // now we can use this timer statment
	counter 1212; // with a counter statment to deref the lcconf ptr and then write anywhere in process memory
	interval 1212 usec;
}
```
If the explanation in text form wasn't enough for you please look at the slides/presentation of both littlelailo and pod2g that have a graphic visualization of the bug.
The bug was "fixed" by Apple in 2012 in iOS 6 as CVE-2012-3727 but fixed the bug in the wrong function (dns4 one) so this bug was not patched until iOS 13.3.1 as CVE-2020-3840.

### ASLR bypass
The aslr bypass is pretty complex to explain but basically there is the dyld shared cache containing all the libraries from apple that gets loaded into each process.
The load base gets randomized on boot by the kernel and for that apple defined a start address and as size. So the kernel will basically use the size of the cache and substract it from the predefined size to get the maximum slide.
This was defined as 1 GB prior to iOS 12 where it was increased to 4 GB "fixing" the bug (we believe that apple never thought this was a secuirty issue and just fixed it by accident because the cache got bigger than 1 GB and so they had to do something about it). 
With each iOS version the cache obviously gets bigger and bigger because Apple adds new functions etc and on iOS 11 this caused a problem because there the cache got bigger than 900 MB.
This means that the maximum slide is now smaller than 100 MB which isn't a problem per se, but the DATA section of the cache is also really big, bigger than 100 MB and with that bigger than the maximum slide.
This basically defeats ASLR complelty because now you always have a writeable address in process memory.
Because the DATA section contains a lot of function pointers we can basically use this to brute force the slide by doing the following:
1. write a slid rop chain at a static address that's always writeable (unslid gadget address + slide xyz)
2. target a random function pointer that's used by the configuration parser (we chose `__platform_memmove`)
3. overwrite that function pointer at it's unslid address + the slide xyz with a gadget that would pivot the stack to our rop chain
4. now trigger the code path in the configuration parser that causes this function pointer to be used (In this case memmove will be used by strlcpy which is used when processing `CFG_DEFAULT_DOMAIN` statments)
5. there are now two possibilites either we guess the right slide so we will jump into our slid rop chain or we guess the wrong one, but nothing happens, we can just try again with a differnt one till we succeed

The exploit for both of these bugs are implemented in stage1.m (logic of the aslr bypass) and `racoon_www.m` (building the config file)

### kASLR leak
The kaslr leak is CVE-2018-4413 and reachable from racoons sandbox. The vulnablility is in the `sysctl_progargsx` function, that gets memory from the heap but doesn't zero it so you can copy out uninizalized heap data and with teh right spraying strategy also kernel pointers.
For a more detailed description see panicalls presentation.
An implementation of the bug is in stuff/CVE-2018-4413/leak.c 

### lightspeed (main kernel bug to get kernel read/write)
There is a really detailed writeup on this bug by synacktiv.
But TL;DR
There is a syscall to handle async file operations (writing a buffer/reading into a buffer) that userland applications can call.
The operation is then handled by a kernel thread and the syscall/kernel thread use a struct they alloc on the heap for each operation to keep track of them.
When the kernel thread is done with the operation it frees the struct.
But if an error occures inside of the syscall code it has to free the struct on it's own to prevent memory leaks.
There is a race window between the syscall reaching this and the kernel thread completing the operation.
So basically the following can happen:
1. syscall allocs struct
2. operation gets added to queue
3. kernel thread performs the operation and frees the struct
4. we reallocate the struct really fast and make sure the second field is 0 (so that the syscall thinks something went wrong)
5. the syscall continues running and frees the struct again

This bug is implemented in pwn.m and also stage2.c (a C implementation of the other thread can be found under stuff/stage2_thread2_implementation.c because at some point I only had the spray thread implemented in rop and use the C program running in parallel to trigger it)

### RootDomainUserClient memory leak we use for spraying
We can't use IOSurface from inside of racoon for spraying because of it's sandbox. That's why we need a memory leak to spray all the objects.
We have access to the RootDomainUserClient and there exists one in it's secureSleepSystemOptions function.
Basically they parse data supplied via XML from userland and then cast it to an OSDictionary, but this cast can fail when we for example pass OSData objects leaking them permanently.

This is used for spraying in racoon so look into stage2.c for the setup

### kASLR weakness
There is a kASLR weakness because the sysctl buffers are stored in the DATA segement of the kernel so they are slid with the same slide the TEXT section of the kernel is splid.
This means that when we know the kernel slide and we can control data of one of the sysctl buffers we can place data at a known address in kernel memory.
We can do this with racoon because it runs as root and we have access to the sysctls from this sandbox.
So we just use swapprefix sysctl and the cool thing about this is that it's a string and the buffer is large enough to pass the original string followed by a zero char and our data.
We can use this to put our fake port at a known address and both new trustcache entries.

## Installation
Obviously, just run `make` to create all generated files (the makefile requires macOS, use a VM or something if you need it).

The app is a *semi-untethered jailbreak*. The app will not install the untether payload.

If you have an issue upgrading essential packages, run `apt --fix-broken install file libplist3 libssl1.1.1` then `apt install -f dpkg ldid -o APT::Immediate-Configure=0` over an SSH connection.

To install the untether payload (these files are located in ./src/untether/generated):
1. Install the DEB file (use `make payload` if you can't find it) or manually copy the stage 1-2 install script to `/private/etc/racoon/install_stage1_2`, stage 3 to `/usr/sbin/racoon.dylib`, and stage 4 to `/mystuff/stage4`.
2. If installing manually, type `/private/etc/racoon/install_stage1_2` in a terminal or SSH connection. This will create the folder `/var/run/racoon` if it does not yet exist.
There will be a lot of output. If successful, the end looks something like:
```
0x1f0214e60: 0x00000000 (NOP)
0x1f0214e68: 0x1e1639494 (code address org:1a1639494) Beast gadget (x30)
=
===
2024-05-11 05:47:33.135 install_stage1_2[4321:134320] Chain will be at: 1afe90d30
2024-05-11 05:47:33.141 install_stage1_2[4321:134320] 4610 iterations
```

If you're running the DEB in Zebra, the last two lines might be replaced with "Finished!".

3. Then execute racoon (the real one in PATH, should be `/usr/sbin/racoon`) till it doesn't kernel panic anymore to make sure you got the right offsets.
If you get a segfault, and the crash report shows the beast gadget offset listed in your output, you likely need to set `STAGE1FD_SCREAM_TEST` to find the right stage 1 fd in the crash log.
If successful, the end looks something like:

```
2024-05-16 00:52:58.174 stage4[597:8713] [jailbreak] generator is set to: 0x1111111111111111
2024-05-16 00:52:58.174 stage4[597:8713] [jailbreak] task_info ret: 0 ((os/kern) successful)
2024-05-16 00:52:58.175 stage4[597:8713] [jailbreak] all_image_info_addr: fffffff00f404000
2024-05-16 00:52:58.175 stage4[597:8713] [jailbreak] all_image_info_size: 8400000
2024-05-16 00:52:58.176 stage4[597:8713] [jailbreak] bundle path: /mystuff
2024-05-16 00:52:58.176 stage4[597:8713] [jailbreak] JBOPT_POST_ONLY mode and bootstrap is present, all is well
2024-05-16 00:52:58.176 stage4[597:8713] [jailbreak] JBOPT_POST_ONLY mode and unrestrict is present, all is well
2024-05-16 00:52:58.181 stage4[597:8713] [jailbreak] wrote offsets.plist
```

If you provide a control-C signal, it will either kernel panic or you might respring and receive more output ending in something like:

```
2024-05-16 01:06:53.425 stage4[597:8713] [jailbreak] finished post exploitation
2024-05-16 01:06:53.425 stage4[597:8713] [jailbreak] unloading prdaily...
2024-05-16 01:06:53.436 stage4[597:8713] [sighandler] Stage 4 received signal: 20
2024-05-16 01:06:53.436 stage4[597:8713] [execprog] contents of /tmp/exec_logs/1715789213:
2024-05-16 01:06:53.437 stage4[597:8713] [jailbreak] prdaily unloaded

iPhone:~ root# 2024-05-16 01:07:18.920 stage4[597:8713] [sighandler] Stage 4 received signal: 20
2024-05-16 01:07:18.920 stage4[597:8713] [execprog] contents of /tmp/exec_logs/1715789213:
2024-05-16 01:07:19.061 stage4[597:8713] [jailbreak] Restoring to mobile and exiting.
2024-05-16 01:07:19.062 stage4[597:8713] [restore_to_mobile] got ourproc at ffffffe0016cd860
2024-05-16 01:07:19.062 stage4[597:8713] [restore_to_mobile] our uid is now 501
```

Another control-C after this will restore control of the SSH connection.

4. Then also set the nvram variable boot-args to "`__developer_mode_enabled`" and check if the system keeps running stable even with racoon (this is the killswitch).
5. If you did you can then go for the real untether by replacing one of the launch daemons and unsetting the killswitch to run the untether on the next boot.

There, you need to watch out for three things:
- the launch daemon isn't used by anything important (namely springboard) (otherwise you will softbrick when it fails to run)
- the launch daemon doesn't have keepalive set (if it does launchd will try to always restart it if you crash it and that will also softbrick)
- the launch daemon starts up early

We found out that you can safely replace prdaily but this one will start really late during boot so you get the same behaviour we also showed in febuary in the demo.
You can also replace wifiFirmwareLoaderLegacy, but this one has keepalive set so you might softbrick. The big advantage you get tho is speed because it starts really early.

If you choose something other than prdaily, you need to update jailbreak.m to unload the right one (currently unloads prdaily) and recompile stage 4/replace it on disk again.
As a last step, please run sync a few times to make sure that everything got written to disk and then fingers crossed it works and you don't softbrick.
If you restart and it keeps kernel panicing, boot into recovery and set the boot-args to "`__developer_mode_enabled`" using irecovery and then reboot this will disable stage 2/the kernel exploit.
If you still can't boot after that you basically softbricked sry.

## References
- writeup on lightspeed (CVE-2018-4344): https://www.synacktiv.com/posts/exploit/lightspeed-a-race-for-an-iosmacos-sandbox-escape.html
- presentation from panicall: https://i.blackhat.com/eu-18/Wed-Dec-5/eu-18-Juwei_Lin-Drill-The-Apple-Core.pdf
- presentation from pod2g https://papers.put.as/papers/ios/2012/pod2g-jailbreak-techniques-wwjc-2012.pdf and https://conference.hitb.org/hitbsecconf2012ams/materials/D2T2%20-%20Jailbreak%20Dream%20Team%20-%20Corona%20Jailbreak%20for%20iOS%205.0.1.pdf
- acron: https://github.com/xerub/acorn

## Credits
- JakeBlair420 team for the actual jailbreak
- Apple for XNU source and leaving CVE-2020-3840 in iOS for years (since iPhoneOS 1.0 if you believe the NVD entry for CVE-2012-3727)
- National Security Agency for [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- planetbeing et al. for [xpwn](https://github.com/planetbeing/xpwn) (specifically xpwntool to decompress the iOS 10 kernel cache)
- PrimePlatypus, LukeZGD, cxdxn1 for explaining that xpwntool exists and how to use it
- blacktop for the [ipsw](https://github.com/blacktop/ipsw) tool (to decompress the iOS 11 kernel cache)
- Jonathan Levin for jtool (version 1, download [here](https://www.newosxbook.com/tools/jtool.tar))
