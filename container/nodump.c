/*
 * nodump.so — LD_PRELOAD library that clears the dumpable flag.
 *
 * When loaded via LD_PRELOAD, the constructor runs after exec() completes
 * (after the kernel's would_dump() has reset dumpable=1 for readable
 * binaries). Setting PR_SET_DUMPABLE=0 from within the process makes
 * /proc/<pid>/mem inaccessible to same-UID processes without CAP_SYS_PTRACE.
 *
 * This replaces the broken drop-dumpable wrapper approach, which set
 * dumpable=0 BEFORE exec — the kernel's would_dump() in fs/exec.c
 * unconditionally resets dumpable=1 when the exec'd binary is readable.
 *
 * Build: gcc -shared -fPIC -O2 -o nodump.so nodump.c
 */
#include <sys/prctl.h>

__attribute__((constructor))
void nodump_init(void) {
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}
