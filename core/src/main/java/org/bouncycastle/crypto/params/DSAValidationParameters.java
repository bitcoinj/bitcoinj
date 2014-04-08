package org.bouncycastle.crypto.params;

import org.bouncycastle.util.Arrays;

public class DSAValidationParameters
{
    private int usageIndex;
    private byte[]  seed;
    private int     counter;

    public DSAValidationParameters(
        byte[]  seed,
        int     counter)
    {
        this(seed, counter, -1);
    }

    public DSAValidationParameters(
        byte[]  seed,
        int     counter,
        int     usageIndex)
    {
        this.seed = seed;
        this.counter = counter;
        this.usageIndex = usageIndex;
    }

    public int getCounter()
    {
        return counter;
    }

    public byte[] getSeed()
    {
        return seed;
    }

    public int getUsageIndex()
    {
        return usageIndex;
    }

    public int hashCode()
    {
        return counter ^ Arrays.hashCode(seed);
    }
    
    public boolean equals(
        Object o)
    {
        if (!(o instanceof DSAValidationParameters))
        {
            return false;
        }

        DSAValidationParameters  other = (DSAValidationParameters)o;

        if (other.counter != this.counter)
        {
            return false;
        }

        return Arrays.areEqual(this.seed, other.seed);
    }
}
