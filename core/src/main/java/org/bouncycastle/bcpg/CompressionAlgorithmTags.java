package org.bouncycastle.bcpg;

/**
 * Basic tags for compression algorithms
 */
public interface CompressionAlgorithmTags 
{
    public static final int UNCOMPRESSED = 0;          // Uncompressed
    public static final int ZIP = 1;                   // ZIP (RFC 1951)
    public static final int ZLIB = 2;                  // ZLIB (RFC 1950)
    public static final int BZIP2 = 3;                 // BZ2
}
