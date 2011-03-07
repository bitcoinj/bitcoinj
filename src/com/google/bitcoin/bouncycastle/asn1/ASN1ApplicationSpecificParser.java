package com.google.bitcoin.bouncycastle.asn1;

import java.io.IOException;

public interface ASN1ApplicationSpecificParser
    extends DEREncodable
{
    DEREncodable readObject()
        throws IOException;
}
