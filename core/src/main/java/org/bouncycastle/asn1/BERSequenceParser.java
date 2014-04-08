package org.bouncycastle.asn1;

import java.io.IOException;

public class BERSequenceParser
    implements ASN1SequenceParser
{
    private ASN1StreamParser _parser;

    BERSequenceParser(ASN1StreamParser parser)
    {
        this._parser = parser;
    }

    public ASN1Encodable readObject()
        throws IOException
    {
        return _parser.readObject();
    }

    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        return new BERSequence(_parser.readVector());
    }
    
    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e.getMessage());
        }
    }
}
