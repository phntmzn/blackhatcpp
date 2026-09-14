// ============================================================
// clip_mon.cpp — poll the clipboard for changes
// ------------------------------------------------------------
// Compile: clang++ -O2 -o clip_mon clip_mon.cpp -framework AppKit
// Run:     ./clip_mon
// ============================================================
#import <AppKit/AppKit.h>
#include <cstdio>
#include <unistd.h>

int main() {
    @autoreleasepool {
        NSInteger last = -1;
        while (true) {
            NSPasteboard* pb = [NSPasteboard generalPasteboard];
            NSInteger cur = [pb changeCount];
            if (cur != last) {
                last = cur;
                NSString* s = [pb stringForType:NSPasteboardTypeString];
                if (s) printf("clip: %s\n", [s UTF8String]);
            }
            usleep(500000);
        }
    }
    return 0;
}
