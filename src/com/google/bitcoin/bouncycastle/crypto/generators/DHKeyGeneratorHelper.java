package com.google.bitcoin.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.google.bitcoin.bouncycastle.crypto.params.DHParameters;
import com.google.bitcoin.bouncycastle.util.BigIntegers;

class DHKeyGeneratorHelper
{
    static final DHKeyGeneratorHelper INSTANCE = new DHKeyGeneratorHelper();

    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private DHKeyGeneratorHelper()
    {
    }

    BigInteger calculatePrivate(DHParameters dhParams, SecureRandom random)
    {
        BigInteger p = dhParams.getP();
        int limit = dhParams.getL();

        if (limit != 0)
        {
            return new BigInteger(limit, random).setBit(limit - 1);
        }

        BigInteger min = TWO;
        int m = dhParams.getM();
        if (m != 0)
        {
            min = ONE.shiftLeft(m - 1);
        }

        BigInteger max = p.subtract(TWO);
        BigInteger q = dhParams.getQ();
        if (q != null)
        {
            max = q.subtract(TWO);
        }

        return BigIntegers.createRandomInRange(min, max, random);
    }

    BigInteger calculatePublic(DHParameters dhParams, BigInteger x)
    {
        return dhParams.getG().modPow(x, dhParams.getP());
    }
}
