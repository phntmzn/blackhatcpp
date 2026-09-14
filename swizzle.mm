// ============================================================
// swizzle.mm — swizzle ObjC methods from injected dylib
// ------------------------------------------------------------
// Compile: clang++ -dynamiclib -ObjC++ -fobjc-arc -std=c++17 -O2 \
//          -o swizzle.dylib swizzle.mm -framework Foundation
// Usage:   DYLD_INSERT_LIBRARIES=./swizzle.dylib ./target
// ============================================================
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

__attribute__((constructor))
static void swizzle_init() {
    Class cls = objc_getClass("NSFileManager");
    SEL sel = @selector(contentsAtPath:);
    Method m = class_getInstanceMethod(cls, sel);

    IMP orig = method_getImplementation(m);
    IMP repl = imp_implementationWithBlock(^id(id self, NSString* path) {
        NSLog(@"[swizzle] contentsAtPath: %@", path);
        return ((id(*)(id, SEL, NSString*))orig)(self, sel, path);
    });
    method_setImplementation(m, repl);
}
