package org.bouncycastle.asn1;

import java.io.IOException;

public interface ASN1SetParser
    extends ASN1Encodable, InMemoryRepresentable
{
    public ASN1Encodable readObject()
        throws IOException;
}
