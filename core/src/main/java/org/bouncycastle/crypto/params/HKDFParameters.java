package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.util.Arrays;

/**
 * Parameter class for the HKDFBytesGenerator class.
 */
public class HKDFParameters
    implements DerivationParameters
{
    private final byte[] ikm;
    private final boolean skipExpand;
    private final byte[] salt;
    private final byte[] info;

    private HKDFParameters(final byte[] ikm, final boolean skip,
                           final byte[] salt, final byte[] info)
    {
        if (ikm == null)
        {
            throw new IllegalArgumentException(
                "IKM (input keying material) should not be null");
        }

        this.ikm = Arrays.clone(ikm);

        this.skipExpand = skip;

        if (salt == null || salt.length == 0)
        {
            this.salt = null;
        }
        else
        {
            this.salt = Arrays.clone(salt);
        }

        if (info == null)
        {
            this.info = new byte[0];
        }
        else
        {
            this.info = Arrays.clone(info);
        }
    }

    /**
     * Generates parameters for HKDF, specifying both the optional salt and
     * optional info. Step 1: Extract won't be skipped.
     *
     * @param ikm  the input keying material or seed
     * @param salt the salt to use, may be null for a salt for hashLen zeros
     * @param info the info to use, may be null for an info field of zero bytes
     */
    public HKDFParameters(final byte[] ikm, final byte[] salt, final byte[] info)
    {
        this(ikm, false, salt, info);
    }

    /**
     * Factory method that makes the HKDF skip the extract part of the key
     * derivation function.
     *
     * @param ikm  the input keying material or seed, directly used for step 2:
     *             Expand
     * @param info the info to use, may be null for an info field of zero bytes
     * @return HKDFParameters that makes the implementation skip step 1
     */
    public static HKDFParameters skipExtractParameters(final byte[] ikm,
                                                       final byte[] info)
    {

        return new HKDFParameters(ikm, true, null, info);
    }

    public static HKDFParameters defaultParameters(final byte[] ikm)
    {
        return new HKDFParameters(ikm, false, null, null);
    }

    /**
     * Returns the input keying material or seed.
     *
     * @return the keying material
     */
    public byte[] getIKM()
    {
        return Arrays.clone(ikm);
    }

    /**
     * Returns if step 1: extract has to be skipped or not
     *
     * @return true for skipping, false for no skipping of step 1
     */
    public boolean skipExtract()
    {
        return skipExpand;
    }

    /**
     * Returns the salt, or null if the salt should be generated as a byte array
     * of HashLen zeros.
     *
     * @return the salt, or null
     */
    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    /**
     * Returns the info field, which may be empty (null is converted to empty).
     *
     * @return the info field, never null
     */
    public byte[] getInfo()
    {
        return Arrays.clone(info);
    }
}
