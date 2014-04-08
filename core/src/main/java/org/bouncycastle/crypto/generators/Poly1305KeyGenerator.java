package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.macs.Poly1305;

/**
 * Generates keys for the Poly1305 MAC.
 * <p>
 * Poly1305 keys are 256 bit keys consisting of a 128 bit secret key used for the underlying block
 * cipher followed by a 128 bit {@code r} value used for the polynomial portion of the Mac. <br>
 * The {@code r} value has a specific format with some bits required to be cleared, resulting in an
 * effective 106 bit key. <br>
 * A separately generated 256 bit key can be modified to fit the Poly1305 key format by using the
 * {@link #clamp(byte[])} method to clear the required bits.
 *
 * @see Poly1305
 */
public class Poly1305KeyGenerator
    extends CipherKeyGenerator
{
    private static final byte R_MASK_LOW_2 = (byte)0xFC;
    private static final byte R_MASK_HIGH_4 = (byte)0x0F;

    /**
     * Initialises the key generator.<br>
     * Poly1305 keys are always 256 bits, so the key length in the provided parameters is ignored.
     */
    public void init(KeyGenerationParameters param)
    {
        // Poly1305 keys are always 256 bits
        super.init(new KeyGenerationParameters(param.getRandom(), 256));
    }

    /**
     * Generates a 256 bit key in the format required for Poly1305 - e.g.
     * <code>k[0] ... k[15], r[0] ... r[15]</code> with the required bits in <code>r</code> cleared
     * as per {@link #clamp(byte[])}.
     */
    public byte[] generateKey()
    {
        final byte[] key = super.generateKey();
        clamp(key);
        return key;
    }

    /**
     * Modifies an existing 32 byte key value to comply with the requirements of the Poly1305 key by
     * clearing required bits in the <code>r</code> (second 16 bytes) portion of the key.<br>
     * Specifically:
     * <ul>
     * <li>r[3], r[7], r[11], r[15] have top four bits clear (i.e., are {0, 1, . . . , 15})</li>
     * <li>r[4], r[8], r[12] have bottom two bits clear (i.e., are in {0, 4, 8, . . . , 252})</li>
     * </ul>
     *
     * @param key a 32 byte key value <code>k[0] ... k[15], r[0] ... r[15]</code>
     */
    public static void clamp(byte[] key)
    {
        /*
         * Key is k[0] ... k[15], r[0] ... r[15] as per poly1305_aes_clamp in ref impl.
         */
        if (key.length != 32)
        {
            throw new IllegalArgumentException("Poly1305 key must be 256 bits.");
        }

        /*
         * r[3], r[7], r[11], r[15] have top four bits clear (i.e., are {0, 1, . . . , 15})
         */
        key[19] &= R_MASK_HIGH_4;
        key[23] &= R_MASK_HIGH_4;
        key[27] &= R_MASK_HIGH_4;
        key[31] &= R_MASK_HIGH_4;

        /*
         * r[4], r[8], r[12] have bottom two bits clear (i.e., are in {0, 4, 8, . . . , 252}).
         */
        key[20] &= R_MASK_LOW_2;
        key[24] &= R_MASK_LOW_2;
        key[28] &= R_MASK_LOW_2;
    }

    /**
     * Checks a 32 byte key for compliance with the Poly1305 key requirements, e.g.
     * <code>k[0] ... k[15], r[0] ... r[15]</code> with the required bits in <code>r</code> cleared
     * as per {@link #clamp(byte[])}.
     *
     * @throws IllegalArgumentException if the key is of the wrong length, or has invalid bits set
     *             in the <code>r</code> portion of the key.
     */
    public static void checkKey(byte[] key)
    {
        if (key.length != 32)
        {
            throw new IllegalArgumentException("Poly1305 key must be 256 bits.");
        }

        checkMask(key[19], R_MASK_HIGH_4);
        checkMask(key[23], R_MASK_HIGH_4);
        checkMask(key[27], R_MASK_HIGH_4);
        checkMask(key[31], R_MASK_HIGH_4);

        checkMask(key[20], R_MASK_LOW_2);
        checkMask(key[24], R_MASK_LOW_2);
        checkMask(key[28], R_MASK_LOW_2);
    }

    private static void checkMask(byte b, byte mask)
    {
        if ((b & (~mask)) != 0)
        {
            throw new IllegalArgumentException("Invalid format for r portion of Poly1305 key.");
        }
    }

}