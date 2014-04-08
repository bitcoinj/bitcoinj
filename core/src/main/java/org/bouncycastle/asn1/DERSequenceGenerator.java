package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class DERSequenceGenerator
    extends DERGenerator
{
    private final ByteArrayOutputStream _bOut = new ByteArrayOutputStream();

    public DERSequenceGenerator(
        OutputStream out)
        throws IOException
    {
        super(out);
    }

    public DERSequenceGenerator(
        OutputStream out,
        int          tagNo,
        boolean      isExplicit)
        throws IOException
    {
        super(out, tagNo, isExplicit);
    }

    public void addObject(
        ASN1Encodable object)
        throws IOException
    {
        object.toASN1Primitive().encode(new DEROutputStream(_bOut));
    }
    
    public OutputStream getRawOutputStream()
    {
        return _bOut;
    }
    
    public void close() 
        throws IOException
    {
        writeDEREncoded(BERTags.CONSTRUCTED | BERTags.SEQUENCE, _bOut.toByteArray());
    }
}
