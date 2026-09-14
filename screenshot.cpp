// ============================================================
// screenshot.cpp — saves PNG of primary screen
// ------------------------------------------------------------
// Compile: clang++ -O2 -o screenshot screenshot.cpp -framework CoreGraphics -framework ImageIO -framework CoreFoundation
// Run:    ./screenshot   (output -> shot.png)
// Note:   Requires Screen Recording permission on macOS 10.15+.
//          Call CGRequestScreenCaptureAccess() first.
// ============================================================
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <cstdio>

int main() {
    CGImageRef img = CGDisplayCreateImage(CGMainDisplayID());
    if (!img) { fprintf(stderr, "capture failed\n"); return 1; }

    CFURLRef url = CFURLCreateWithFileSystemPath(
        kCFAllocatorDefault, CFSTR("shot.png"),
        kCFURLPOSIXPathStyle, false);

    CGImageDestinationRef dst = CGImageDestinationCreateWithURL(
        url, CFSTR("public.png"), 1, nullptr);
    CGImageDestinationAddImage(dst, img, nullptr);
    CGImageDestinationFinalize(dst);

    CFRelease(dst); CFRelease(url); CGImageRelease(img);
    printf("saved shot.png\n");
    return 0;
}
