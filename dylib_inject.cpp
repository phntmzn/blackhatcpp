// ============================================================
// dylib_inject.cpp — force remote process to dlopen(your.dylib)
// ------------------------------------------------------------
// Compile: clang++ -O2 -o dylib_inject dylib_inject.cpp -framework CoreFoundation
// Usage:   sudo ./dylib_inject <pid> /path/to/payload.dylib
// Note:    Requires root + debuggable target (get-task-allow).
//          Same SIP/entitlement restrictions as injection above.
// ============================================================
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>

int main(int argc, char** argv) {
    if (argc < 3) { printf("usage: %s <pid> <dylib>\n", argv[0]); return 1; }
    pid_t pid = atoi(argv[1]);
    const char* dylib = argv[2];

    task_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed: %s\n", mach_error_string(kr));
        return 1;
    }

    // Allocate and write dylib path
    mach_vm_address_t path_addr;
    mach_vm_allocate(task, &path_addr, strlen(dylib) + 1, VM_FLAGS_ANYWHERE);
    mach_vm_write(task, path_addr, (vm_offset_t)dylib, strlen(dylib) + 1);

    // Build stub: call dlopen(path, RTLD_NOW)
    // In practice, you'd build shellcode that calls dlopen.
    // Simplified: allocate, write, and hijack thread RIP to a dlopen stub.
    // (Full implementation requires arch-specific assembly stub.)
    printf("path written to 0x%llx\n", (unsigned long long)path_addr);

    // Resolve dlopen address in this process (shared cache, same for target)
    void* dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
    printf("dlopen at %p\n", dlopen_addr);
    return 0;
}
