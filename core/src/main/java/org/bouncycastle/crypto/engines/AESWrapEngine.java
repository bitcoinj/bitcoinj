package org.bouncycastle.crypto.engines;

/**
 * an implementation of the AES Key Wrapper from the NIST Key Wrap
 * Specification.
 * <p>
 * For further details see: <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
 */
public class AESWrapEngine
    extends RFC3394WrapEngine
{
    public AESWrapEngine()
    {
        super(new AESEngine());
    }
}
