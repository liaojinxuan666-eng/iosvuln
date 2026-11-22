// iosvuln - EXTRACTIVE ElleKit tweak
// This tweak does NOT hook or modify any function. It only resolves symbols
// with MSFindSymbol (Substrate-compatible API provided by ElleKit) and writes
// each function's address + raw instruction bytes to a JSON file on device.
// Off-device, iosvuln disassembles those addresses and reports vulnerability
// primitives. Install the resulting .deb with Sileo.

#include <substrate.h>
#include <dlfcn.h>
#include <Foundation/Foundation.h>

static NSString *const kOutPath = @"/var/mobile/iosvuln/extracted.json";

static NSArray *ExtractSymbols(void) {
    const char *names[] = {
        "IOSurfaceCreate",
        "IOSurfaceSetValue",
        "IOSurfaceCopyValue",
        "IOSurfaceRemoveValue",
        "IOSurfaceLock",
        "IOSurfaceUnlock",
        "IOSurfaceGetBaseAddress",
        "IOSurfaceGetAllocSize",
        "IOSurfaceCreateMachPort",
        "IOSurfaceLookupFromMachPort",
        "IOSurfaceIncrementUseCount",
        "IOSurfaceDecrementUseCount",
    };
    NSMutableArray *result = [NSMutableArray array];
    size_t count = sizeof(names) / sizeof(names[0]);
    for (size_t i = 0; i < count; i++) {
        void *addr = MSFindSymbol(NULL, names[i]);
        if (!addr) continue;
        NSMutableString *hex = [NSMutableString stringWithCapacity:128];
        uint8_t *bytes = (uint8_t *)addr;
        for (int j = 0; j < 96; j++) {
            [hex appendFormat:@"%02x", bytes[j]];
        }
        [result addObject:@{
            @"name": [NSString stringWithUTF8String:names[i]],
            @"address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)(uintptr_t)addr],
            @"bytes": hex,
            @"length": @96,
        }];
    }
    return result;
}

__attribute__((constructor)) static void iosvuln_extract_init(void) {
    @autoreleasepool {
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm createDirectoryAtPath:@"/var/mobile/iosvuln"
      withIntermediateDirectories:YES
                       attributes:nil
                            error:nil];
        NSDictionary *payload = @{
            @"target": @"IOSurface.framework",
            @"mode": @"extractive",
            @"functions": ExtractSymbols(),
        };
        NSData *data = [NSJSONSerialization dataWithJSONObject:payload
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:nil];
        [data writeToFile:kOutPath atomically:YES];
    }
}
