// ============================================================
// spawn_hollow.cpp — spawn a process and redirect its stdin/out
// ------------------------------------------------------------
// Compile: clang++ -O2 -o spawn_hollow spawn_hollow.cpp
// Usage:   ./spawn_hollow /bin/sh
// ============================================================
#include <spawn.h>
#include <unistd.h>
#include <cstdio>

extern char** environ;

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    int p[2];
    pipe(p);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[0], 0);
    posix_spawn_file_actions_adddup2(&fa, p[1], 1);
    posix_spawn_file_actions_adddup2(&fa, p[1], 2);

    pid_t pid;
    posix_spawn(&pid, argv[1], &fa, nullptr, argv, environ);
    printf("spawned pid=%d\n", pid);
    return 0;
}
