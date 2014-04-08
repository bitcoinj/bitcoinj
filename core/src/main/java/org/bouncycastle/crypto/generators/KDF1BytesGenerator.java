package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.Digest;

/**
 * KDF1 generator for derived keys and ivs as defined by IEEE P1363a/ISO 18033
 * <br>
 * This implementation is based on ISO 18033/IEEE P1363a.
 */
public class KDF1BytesGenerator
    extends BaseKDFBytesGenerator
{
    /**
     * Construct a KDF1 byte generator.
     * <p>
     * @param digest the digest to be used as the source of derived keys.
     */
    public KDF1BytesGenerator(
        Digest  digest)
    {
        super(0, digest);
    }
}
