// ============================================================
// cam_grab.cpp — open default camera (no frames saved)
// ------------------------------------------------------------
// Compile: clang++ -O2 -o cam_grab cam_grab.cpp -framework AVFoundation -framework CoreMedia -framework CoreVideo -fobjc-arc
// Run:     ./cam_grab
// Note:    Triggers TCC camera prompt on first run.
// ============================================================
#import <AVFoundation/AVFoundation.h>
#include <cstdio>

int main() {
    @autoreleasepool {
        AVCaptureDevice* dev = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];
        if (!dev) { fprintf(stderr, "no camera\n"); return 1; }
        printf("camera: %s\n", [[dev localizedName] UTF8String]);
        [AVCaptureDevice requestAccessForMediaType:AVMediaTypeVideo
            completionHandler:^(BOOL granted) {
                printf("granted: %d\n", granted);
            }];
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:5]];
    }
    return 0;
}
