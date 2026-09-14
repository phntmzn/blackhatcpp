// ============================================================
// mic_probe.cpp — request microphone permission
// ------------------------------------------------------------
// Compile: clang++ -O2 -o mic_probe mic_probe.cpp -framework AVFoundation -fobjc-arc
// Run:     ./mic_probe
// ============================================================
#import <AVFoundation/AVFoundation.h>
#include <cstdio>

int main() {
    @autoreleasepool {
        [AVCaptureDevice requestAccessForMediaType:AVMediaTypeAudio
            completionHandler:^(BOOL granted) {
                printf("mic granted: %d\n", granted);
            }];
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:5]];
    }
    return 0;
}
