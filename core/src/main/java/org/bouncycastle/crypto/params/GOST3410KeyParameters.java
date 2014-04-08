package org.bouncycastle.crypto.params;

public class GOST3410KeyParameters
        extends AsymmetricKeyParameter
{
    private GOST3410Parameters    params;

    public GOST3410KeyParameters(
        boolean         isPrivate,
        GOST3410Parameters   params)
    {
        super(isPrivate);

        this.params = params;
    }

    public GOST3410Parameters getParameters()
    {
        return params;
    }
}
