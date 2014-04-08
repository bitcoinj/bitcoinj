package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.util.Arrays;

public final class KDFCounterParameters
    implements DerivationParameters
{

    private final byte[] ki;
    private final byte[] fixedInputData;
    private final int r;

    public KDFCounterParameters(byte[] ki, byte[] fixedInputData, int r)
    {
        if (ki == null)
        {
            throw new IllegalArgumentException("A KDF requires Ki (a seed) as input");
        }
        this.ki = Arrays.clone(ki);

        if (fixedInputData == null)
        {
            this.fixedInputData = new byte[0];
        }
        else
        {
            this.fixedInputData = Arrays.clone(fixedInputData);
        }

        if (r != 8 && r != 16 && r != 24 && r != 32)
        {
            throw new IllegalArgumentException("Length of counter should be 8, 16, 24 or 32");
        }
        this.r = r;
    }

    public byte[] getKI()
    {
        return ki;
    }

    public byte[] getFixedInputData()
    {
        return Arrays.clone(fixedInputData);
    }

    public int getR()
    {
        return r;
    }
}
