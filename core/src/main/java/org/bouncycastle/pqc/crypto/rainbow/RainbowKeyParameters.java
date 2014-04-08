package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class RainbowKeyParameters 
    extends AsymmetricKeyParameter
{
    private int docLength;

    public RainbowKeyParameters(
            boolean         isPrivate,
            int             docLength)
    {
        super(isPrivate);
        this.docLength = docLength;
    }

    /**
     * @return the docLength
     */
    public int getDocLength()
    {
        return this.docLength;
    }
}
