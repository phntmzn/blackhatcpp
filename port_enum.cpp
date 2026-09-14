// ============================================================
// port_enum.cpp — list Mach port rights in current task
// ------------------------------------------------------------
// Compile: clang++ -O2 -o port_enum port_enum.cpp
// Run:     ./port_enum
// ============================================================
#include <mach/mach.h>
#include <cstdio>

int main() {
    mach_port_name_array_t names;
    mach_msg_type_number_t namesCnt;
    mach_port_type_array_t types;
    mach_msg_type_number_t typesCnt;

    if (mach_port_names(mach_task_self(), &names, &namesCnt,
                        &types, &typesCnt) != KERN_SUCCESS) return 1;

    for (unsigned i = 0; i < namesCnt; i++) {
        const char* kind = "?";
        if (types[i] & MACH_PORT_TYPE_SEND)    kind = "SEND";
        if (types[i] & MACH_PORT_TYPE_RECEIVE) kind = "RECV";
        printf("port %-8u type=0x%x (%s)\n", names[i], types[i], kind);
    }
    return 0;
}
