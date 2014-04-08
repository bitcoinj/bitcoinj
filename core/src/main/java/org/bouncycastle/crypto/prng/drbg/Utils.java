package org.bouncycastle.crypto.prng.drbg;

import java.util.Hashtable;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.util.Integers;

class Utils
{
    static final Hashtable maxSecurityStrengths = new Hashtable();

    static
    {
        maxSecurityStrengths.put("SHA-1", Integers.valueOf(128));

        maxSecurityStrengths.put("SHA-224", Integers.valueOf(192));
        maxSecurityStrengths.put("SHA-256", Integers.valueOf(256));
        maxSecurityStrengths.put("SHA-384", Integers.valueOf(256));
        maxSecurityStrengths.put("SHA-512", Integers.valueOf(256));

        maxSecurityStrengths.put("SHA-512/224", Integers.valueOf(192));
        maxSecurityStrengths.put("SHA-512/256", Integers.valueOf(256));
    }

    static int getMaxSecurityStrength(Digest d)
    {
        return ((Integer)maxSecurityStrengths.get(d.getAlgorithmName())).intValue();
    }

    static int getMaxSecurityStrength(Mac m)
    {
        String name = m.getAlgorithmName();

        return ((Integer)maxSecurityStrengths.get(name.substring(0, name.indexOf("/")))).intValue();
    }

    /**
     * Used by both Dual EC and Hash.
     */
    static byte[] hash_df(Digest digest, byte[] seedMaterial, int seedLength)
    {
         // 1. temp = the Null string.
        // 2. .
        // 3. counter = an 8-bit binary value representing the integer "1".
        // 4. For i = 1 to len do
        // Comment : In step 4.1, no_of_bits_to_return
        // is used as a 32-bit string.
        // 4.1 temp = temp || Hash (counter || no_of_bits_to_return ||
        // input_string).
        // 4.2 counter = counter + 1.
        // 5. requested_bits = Leftmost (no_of_bits_to_return) of temp.
        // 6. Return SUCCESS and requested_bits.
        byte[] temp = new byte[(seedLength + 7) / 8];

        int len = temp.length / digest.getDigestSize();
        int counter = 1;

        byte[] dig = new byte[digest.getDigestSize()];

        for (int i = 0; i <= len; i++)
        {
            digest.update((byte)counter);

            digest.update((byte)(seedLength >> 24));
            digest.update((byte)(seedLength >> 16));
            digest.update((byte)(seedLength >> 8));
            digest.update((byte)seedLength);

            digest.update(seedMaterial, 0, seedMaterial.length);

            digest.doFinal(dig, 0);

            int bytesToCopy = ((temp.length - i * dig.length) > dig.length)
                    ? dig.length
                    : (temp.length - i * dig.length);
            System.arraycopy(dig, 0, temp, i * dig.length, bytesToCopy);

            counter++;
        }

        // do a left shift to get rid of excess bits.
        if (seedLength % 8 != 0)
        {
            int shift = 8 - (seedLength % 8);
            int carry = 0;

            for (int i = 0; i != temp.length; i++)
            {
                int b = temp[i] & 0xff;
                temp[i] = (byte)((b >>> shift) | (carry << (8 - shift)));
                carry = b;
            }
        }

        return temp;
    }

    static boolean isTooLarge(byte[] bytes, int maxBytes)
    {
        return bytes != null && bytes.length > maxBytes;
    }
}
