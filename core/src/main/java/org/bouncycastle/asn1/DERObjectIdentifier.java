package org.bouncycastle.asn1;

/**
 *
 * @deprecated Use ASN1ObjectIdentifier instead of this,
 */
public class DERObjectIdentifier
    extends ASN1ObjectIdentifier
{
    public DERObjectIdentifier(String identifier)
    {
        super(identifier);
    }

    DERObjectIdentifier(byte[] bytes)
    {
        super(bytes);
    }

    DERObjectIdentifier(ASN1ObjectIdentifier oid, String branch)
    {
        super(oid, branch);
    }
}
