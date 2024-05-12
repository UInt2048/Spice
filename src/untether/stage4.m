#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <Foundation/NSObjCRuntime.h>
#include <shared/jailbreak.h>

// used to catch all signals
void sighandler(int signo) {
	LOG("Stage 4 received signal: %d",signo);
}

int main() {
	// just catch all the signals here so that we catch the SIGKILL from launchd and don't exit
	// NOTE: This is really stupid because you can't catch a SIGKILL
	for (int i = 0; i < 32; i++) {signal(i,sighandler);}
	// call out to the post exploitation framework (implemented under shared)
	jailbreak(JBOPT_POST_ONLY);
}