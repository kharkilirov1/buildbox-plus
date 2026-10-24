// Bridging header for zsign C API + the Rust sideload engine bridge
#import <Foundation/Foundation.h>
#import "buildbox_sideload.h"

bool CheckIfSigned(NSString *filePath);

int zsign(
    NSString *app,
    NSString *prov,
    NSString *key,
    NSString *pass,
    NSString *entitlement,
    NSString *bundleid,
    NSString *displayname,
    NSString *bundleversion,
    bool adhoc,
    bool dontGenerateEmbeddedMobileProvision,
    void(^completionHandler)(BOOL success)
);

/// Raw-DEFLATE inflate via the vendored zlib (see bbinflate.c).
/// Returns 0 on success; outLen receives the decompressed byte count.
int bb_inflate_raw(const unsigned char *src, unsigned long srcLen,
                   unsigned char *dst, unsigned long dstCap,
                   unsigned long *outLen);

/// Raw-DEFLATE compression via the vendored zlib (see bbinflate.c).
/// Returns 0 on success; outLen receives the compressed byte count.
int bb_deflate_raw(const unsigned char *src, unsigned long srcLen,
                   unsigned char *dst, unsigned long dstCap,
                   unsigned long *outLen);

/// zlib-format compression via the vendored zlib (see bbinflate.c).
/// Returns 0 on success; outLen receives the compressed byte count.
int bb_zlib_compress(const unsigned char *src, unsigned long srcLen,
                     unsigned char *dst, unsigned long dstCap,
                     unsigned long *outLen);
