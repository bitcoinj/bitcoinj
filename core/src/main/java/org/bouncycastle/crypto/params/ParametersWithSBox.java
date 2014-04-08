package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

public class ParametersWithSBox
    implements CipherParameters
{
    private CipherParameters  parameters;
    private byte[]            sBox;

    public ParametersWithSBox(
        CipherParameters parameters,
        byte[]           sBox)
    {
        this.parameters = parameters;
        this.sBox = sBox;
    }

    public byte[] getSBox()
    {
        return sBox;
    }

    public CipherParameters getParameters()
    {
        return parameters;
    }
}
