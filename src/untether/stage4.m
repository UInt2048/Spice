#include <Foundation/NSObjCRuntime.h>
#include <fcntl.h>
#include <shared/jailbreak.h>
#include <stdio.h>
#include <unistd.h>

// used to catch all signals
void sighandler(int signo)
{
    LOG("Stage 4 received signal: %d", signo);
}

// Do nothing when we move to the next stage
void sendLog(void* controller, NSString* log) { }

int main()
{
    // just catch all the signals here so that we catch the SIGKILL from launchd and don't exit
    // NOTE: This is really stupid because you can't catch a SIGKILL
    for (int i = 0; i < 32; i++) {
        signal(i, sighandler);
    }
    // call out to the post exploitation framework (implemented under shared)
    jailbreak(JBOPT_EXPLOIT_AUTO | JBOPT_POST_ONLY, NULL, &sendLog);
}
