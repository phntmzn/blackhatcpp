// ============================================================
// mem_scan.cpp — search for pattern in target process memory
// ------------------------------------------------------------
// Compile: clang++ -O2 -o mem_scan mem_scan.cpp
// Usage:   sudo ./mem_scan <pid> <hexbyte>
// Note:    task_for_pid restrictions apply.
// ============================================================
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    pid_t pid = atoi(argv[1]);
    unsigned char needle = (unsigned char)strtol(argv[2], nullptr, 16);

    task_t task;
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) return 1;

    mach_vm_address_t addr = 0;
    mach_vm_size_t size;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj;

    while (true) {
        if (mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                          (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if (info.protection & VM_PROT_READ) {
            void* buf = malloc(size);
            mach_vm_size_t read;
            if (mach_vm_read_overwrite(task, addr, size,
                    (mach_vm_address_t)buf, &read) == KERN_SUCCESS) {
                for (mach_vm_size_t i = 0; i < read; i++)
                    if (((unsigned char*)buf)[i] == needle)
                        printf("hit @ 0x%llx\n",
                               (unsigned long long)(addr + i));
            }
            free(buf);
        }
        addr += size;
    }
    return 0;
}
