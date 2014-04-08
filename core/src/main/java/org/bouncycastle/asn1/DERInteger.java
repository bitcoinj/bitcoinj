package org.bouncycastle.asn1;

import java.math.BigInteger;

/**
 * @deprecated  Use ASN1Integer instead of this,
 */
public class DERInteger
    extends ASN1Integer
{
    /**
     * Constructor from a byte array containing a signed representation of the number.
     *
     * @param bytes a byte array containing the signed number.A copy is made of the byte array.
     */
    public DERInteger(byte[] bytes)
    {
        super(bytes, true);
    }

    public DERInteger(BigInteger value)
    {
        super(value);
    }

    public DERInteger(long value)
    {
        super(value);
    }
}
