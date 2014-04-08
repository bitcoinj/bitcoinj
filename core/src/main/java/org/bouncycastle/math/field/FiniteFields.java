package org.bouncycastle.math.field;

import java.math.BigInteger;

public abstract class FiniteFields
{
    static final FiniteField GF_2 = new PrimeField(BigInteger.valueOf(2));
    static final FiniteField GF_3 = new PrimeField(BigInteger.valueOf(3));

    public static PolynomialExtensionField getBinaryExtensionField(int[] exponents)
    {
        if (exponents[0] != 0)
        {
            throw new IllegalArgumentException("Irreducible polynomials in GF(2) must have constant term");
        }
        for (int i = 1; i < exponents.length; ++i)
        {
            if (exponents[i] <= exponents[i - 1])
            {
                throw new IllegalArgumentException("Polynomial exponents must be montonically increasing");
            }
        }

        return new GenericPolynomialExtensionField(GF_2, new GF2Polynomial(exponents));
    }

//    public static PolynomialExtensionField getTernaryExtensionField(Term[] terms)
//    {
//        return new GenericPolynomialExtensionField(GF_3, new GF3Polynomial(terms));
//    }

    public static FiniteField getPrimeField(BigInteger characteristic)
    {
        int bitLength = characteristic.bitLength();
        if (characteristic.signum() <= 0 || bitLength < 2)
        {
            throw new IllegalArgumentException("'characteristic' must be >= 2");
        }

        if (bitLength < 3)
        {
            switch (characteristic.intValue())
            {
            case 2:
                return GF_2;
            case 3:
                return GF_3;
            }
        }

        return new PrimeField(characteristic);
    }
}
