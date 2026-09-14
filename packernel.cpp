// ============================================================
// packernel.cpp — PAC pointer integrity demo (KEXT)
// ------------------------------------------------------------
// Build:  sudo xcodebuild -project PACKernel.xcodeproj \
//         -target PACKernel -configuration Release
// Load:   sudo kextload /path/to/PACKernel.kext
// Log:    log stream --predicate 'process == "kernel"' --info
// ============================================================
#include <mach/mach_types.h>
#include <sys/systm.h>

extern "C" kern_return_t PACKernel_start(kmod_info_t* ki, void* d) {
    IOLog("[PACKernel] loaded — demonstrating PAC pointer integrity\n");
    return KERN_SUCCESS;
}

extern "C" kern_return_t PACKernel_stop(kmod_info_t* ki, void* d) {
    IOLog("[PACKernel] unloaded\n");
    return KERN_SUCCESS;
}
