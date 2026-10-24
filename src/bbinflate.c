// Raw-DEFLATE decompression backed by the zlib already vendored inside
// zsign (third-party/zlib) — the same C code every fast signer uses.
// Exposed to Swift through Bridging.h as the reliable inflate path for
// IPASigner (the Compression-framework stream kept misbehaving on large
// entries: no END without FINALIZE games, trailer checks, fallbacks).
#include "zsign/third-party/zlib/zlib.h"

/// Inflates raw DEFLATE data (ZIP entries, RFC 1951) into dst.
/// Returns 0 on success and sets *outLen; non-zero on failure.
int bb_inflate_raw(const unsigned char *src, unsigned long srcLen,
                   unsigned char *dst, unsigned long dstCap,
                   unsigned long *outLen) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = (Bytef *)src;
    strm.avail_in = (uInt)srcLen;
    strm.next_out = (Bytef *)dst;
    strm.avail_out = (uInt)dstCap;
    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) return -1;
    int ret = inflate(&strm, Z_FINISH);
    unsigned long produced = strm.total_out;
    inflateEnd(&strm);
    if (ret != Z_STREAM_END) return -2;
    if (outLen) *outLen = produced;
    return 0;
}

/// Compresses data as raw DEFLATE into dst (caller-sized, e.g. via
/// deflateBound logic: srcLen + srcLen/8 + 64 is a safe upper bound).
/// Returns 0 on success and sets *outLen; non-zero on failure.
/// Used by IPASigner's zip writer so signed IPAs are stored DEFLATED —
/// the store-only writer doubled library sizes (a 350 MB IPA became
/// 684 MB), which fills a phone fast when users sign everything.
int bb_deflate_raw(const unsigned char *src, unsigned long srcLen,
                   unsigned char *dst, unsigned long dstCap,
                   unsigned long *outLen) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = (Bytef *)src;
    strm.avail_in = (uInt)srcLen;
    strm.next_out = (Bytef *)dst;
    strm.avail_out = (uInt)dstCap;
    if (deflateInit2(&strm, 6, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) return -1;
    int ret = deflate(&strm, Z_FINISH);
    unsigned long produced = strm.total_out;
    deflateEnd(&strm);
    if (ret != Z_STREAM_END) return -2;
    if (outLen) *outLen = produced;
    return 0;
}

/* zlib-format compression (for rebuilding standard PNGs from normalized
   CgBI pixels). Returns 0 on success; outLen gets the byte count. */
int bb_zlib_compress(const unsigned char *src, unsigned long srcLen,
                     unsigned char *dst, unsigned long dstCap,
                     unsigned long *outLen) {
    uLongf bound = compressBound((uLong)srcLen);
    if (bound > dstCap) return -1;
    uLongf out = (uLongf)dstCap;
    if (compress2(dst, &out, src, (uLong)srcLen, 6) != Z_OK) return -1;
    *outLen = (unsigned long)out;
    return 0;
}
