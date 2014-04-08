package org.bouncycastle.asn1;

/**
 * @deprecated use ASN1Boolean
 */
public class DERBoolean
    extends ASN1Boolean
{
    /**
     * @deprecated use getInstance(boolean) method.
     * @param value
     */
    public DERBoolean(boolean value)
    {
        super(value);
    }

    DERBoolean(byte[] value)
    {
        super(value);
    }
}
