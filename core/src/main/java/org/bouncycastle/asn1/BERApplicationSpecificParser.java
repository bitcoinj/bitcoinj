package org.bouncycastle.asn1;

import java.io.IOException;

public class BERApplicationSpecificParser
    implements ASN1ApplicationSpecificParser
{
    private final int tag;
    private final ASN1StreamParser parser;

    BERApplicationSpecificParser(int tag, ASN1StreamParser parser)
    {
        this.tag = tag;
        this.parser = parser;
    }

    public ASN1Encodable readObject()
        throws IOException
    {
        return parser.readObject();
    }

    public ASN1Primitive getLoadedObject()
        throws IOException
    {
         return new BERApplicationSpecific(tag, parser.readVector());
    }

    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (IOException e)
        {
            throw new ASN1ParsingException(e.getMessage(), e);
        }
    }

}
