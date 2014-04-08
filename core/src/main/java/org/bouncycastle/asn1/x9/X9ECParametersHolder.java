package org.bouncycastle.asn1.x9;

public abstract class X9ECParametersHolder
{
    private X9ECParameters params;

    public X9ECParameters getParameters()
    {
        if (params == null)
        {
            params = createParameters();
        }

        return params;
    }

    protected abstract X9ECParameters createParameters();
}
