package org.bouncycastle.asn1.esf;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;

public class SPuri
{
    private DERIA5String uri;

    public static SPuri getInstance(
        Object obj)
    {
        if (obj instanceof SPuri)
        {
            return (SPuri) obj;
        }
        else if (obj instanceof DERIA5String)
        {
            return new SPuri(DERIA5String.getInstance(obj));
        }

        return null;
    }

    public SPuri(
        DERIA5String uri)
    {
        this.uri = uri;
    }

    public DERIA5String getUri()
    {
        return uri;
    }

    /**
     * <pre>
     * SPuri ::= IA5String
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return uri.toASN1Primitive();
    }
}
