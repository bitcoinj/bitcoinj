package org.bouncycastle.asn1;

import java.io.IOException;

public class BERTaggedObjectParser
    implements ASN1TaggedObjectParser
{
    private boolean _constructed;
    private int _tagNumber;
    private ASN1StreamParser _parser;

    BERTaggedObjectParser(
        boolean             constructed,
        int                 tagNumber,
        ASN1StreamParser    parser)
    {
        _constructed = constructed;
        _tagNumber = tagNumber;
        _parser = parser;
    }

    public boolean isConstructed()
    {
        return _constructed;
    }

    public int getTagNo()
    {
        return _tagNumber;
    }

    public ASN1Encodable getObjectParser(
        int     tag,
        boolean isExplicit)
        throws IOException
    {
        if (isExplicit)
        {
            if (!_constructed)
            {
                throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
            }
            return _parser.readObject();
        }

        return _parser.readImplicit(_constructed, tag);
    }

    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        return _parser.readTaggedObject(_constructed, _tagNumber);
    }

    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return this.getLoadedObject();
        }
        catch (IOException e)
        {
            throw new ASN1ParsingException(e.getMessage());
        }
    }
}
