package org.bouncycastle.asn1;

import java.io.IOException;

public interface ASN1TaggedObjectParser
    extends ASN1Encodable, InMemoryRepresentable
{
    public int getTagNo();
    
    public ASN1Encodable getObjectParser(int tag, boolean isExplicit)
        throws IOException;
}
