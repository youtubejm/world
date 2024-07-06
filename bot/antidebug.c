#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>

// Function to be called when a debugger is detected
static void debugger_detected(int signo)
{
    #ifdef DEBUG
    printf("Debugger detected! Exiting...\n");
    #endif
    usleep(1000000); // Sleep for 1 second (adjust as needed)
    exit(EXIT_FAILURE);
}

// Function to initialize anti-debugging measures
void antidebug(void)
{
    // Set up a signal handler to detect debugger
    signal(SIGTRAP, debugger_detected);

    // Check for debugger using ptrace
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1)
    {
        #ifdef DEBUG
        printf("Debugger detected! Exiting...\n");
        #endif
        usleep(1000000); // Sleep for 1 second (adjust as needed)
        exit(EXIT_FAILURE);
    }
}

