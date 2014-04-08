package org.bouncycastle.crypto.ec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECConstants;

class ECUtil
{
    static BigInteger generateK(BigInteger n, SecureRandom random)
    {
        int nBitLength = n.bitLength();
        BigInteger k;
        do
        {
            k = new BigInteger(nBitLength, random);
        }
        while (k.equals(ECConstants.ZERO) || (k.compareTo(n) >= 0));
        return k;
    }
}
