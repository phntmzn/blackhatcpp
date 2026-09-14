// ============================================================
// bt_scan.cpp — scan Bluetooth devices (macOS IOBluetooth)
// ------------------------------------------------------------
// Compile: clang++ -ObjC++ -std=c++17 -O2 -fobjc-arc \
//          -o bt_scan bt_scan.cpp -framework IOBluetooth -framework Foundation
// Usage:   ./bt_scan
// Note:    Requires Bluetooth permission prompt.
// ============================================================
#import <IOBluetooth/IOBluetooth.h>
#include <cstdio>

int main() {
    @autoreleasepool {
        NSArray* devices = [IOBluetoothDevice pairedDevices];
        for (IOBluetoothDevice* d in devices)
            std::printf("%s %s\n",
                [[d getName] UTF8String],
                [[d getAddressString] UTF8String]);

        IOBluetoothDeviceInquiry* inq = [IOBluetoothDeviceInquiry inquiryWithDelegate:nil];
        [inq setInquiryLength:8];
        [inq start];
        std::printf("[*] inquiry started\n");
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:10]];
    }
    return 0;
}
