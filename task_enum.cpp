// ============================================================
// task_enum.cpp — list tasks you can get a port to
// ------------------------------------------------------------
// Compile: clang++ -O2 -o task_enum task_enum.cpp
// Run:     sudo ./task_enum
// Note:    Enumerates all PIDs; task_for_pid will fail for most.
// ============================================================
#include <mach/mach.h>
#include <libproc.h>
#include <cstdio>
#include <vector>

int main() {
    int pids[4096];
    int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    n /= sizeof(int);
    for (int i = 0; i < n; i++) {
        if (!pids[i]) continue;
        task_t t;
        if (task_for_pid(mach_task_self(), pids[i], &t) == KERN_SUCCESS) {
            char name[PROC_PIDPATHINFO_MAXSIZE] = {0};
            proc_pidpath(pids[i], name, sizeof(name));
            printf("pid=%d task=%u %s\n", pids[i], t, name);
            mach_port_deallocate(mach_task_self(), t);
        }
    }
    return 0;
}
