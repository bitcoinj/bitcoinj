package org.bouncycastle.crypto.params;

/**
 * @deprecated use AEADParameters
 */
public class CCMParameters
    extends AEADParameters
{
    /**
     * Base constructor.
     * 
     * @param key key to be used by underlying cipher
     * @param macSize macSize in bits
     * @param nonce nonce to be used
     * @param associatedText associated text, if any
     */
    public CCMParameters(KeyParameter key, int macSize, byte[] nonce, byte[] associatedText)
    {
        super(key, macSize, nonce, associatedText);
    }
}
