package org.bouncycastle.math.field;

import java.math.BigInteger;

class PrimeField implements FiniteField
{
    protected final BigInteger characteristic;

    PrimeField(BigInteger characteristic)
    {
        this.characteristic = characteristic;
    }

    public BigInteger getCharacteristic()
    {
        return characteristic;
    }

    public int getDimension()
    {
        return 1;
    }

    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (!(obj instanceof PrimeField))
        {
            return false;
        }
        PrimeField other = (PrimeField)obj;
        return characteristic.equals(other.characteristic);
    }

    public int hashCode()
    {
        return characteristic.hashCode();
    }
}
