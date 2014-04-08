package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.Arrays;

/**
 * Parameters for tweakable block ciphers.
 */
public class TweakableBlockCipherParameters
    implements CipherParameters
{
    private final byte[] tweak;
    private final KeyParameter key;

    public TweakableBlockCipherParameters(final KeyParameter key, final byte[] tweak)
    {
        this.key = key;
        this.tweak = Arrays.clone(tweak);
    }

    /**
     * Gets the key.
     *
     * @return the key to use, or <code>null</code> to use the current key.
     */
    public KeyParameter getKey()
    {
        return key;
    }

    /**
     * Gets the tweak value.
     *
     * @return the tweak to use, or <code>null</code> to use the current tweak.
     */
    public byte[] getTweak()
    {
        return tweak;
    }
}
