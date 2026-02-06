#include <sys/prctl.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: drop-dumpable COMMAND [ARGS...]\n");
        return 1;
    }
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    execvp(argv[1], &argv[1]);
    perror("exec");
    return 1;
}
