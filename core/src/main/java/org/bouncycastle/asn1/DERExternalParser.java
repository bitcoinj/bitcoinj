package org.bouncycastle.asn1;

import java.io.IOException;

public class DERExternalParser
    implements ASN1Encodable, InMemoryRepresentable
{
    private ASN1StreamParser _parser;

    /**
     * 
     */
    public DERExternalParser(ASN1StreamParser parser)
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
        try
        {
            return new DERExternal(_parser.readVector());
        }
        catch (IllegalArgumentException e)
        {
            throw new ASN1Exception(e.getMessage(), e);
        }
    }
    
    public ASN1Primitive toASN1Primitive()
    {
        try 
        {
            return getLoadedObject();
        }
        catch (IOException ioe) 
        {
            throw new ASN1ParsingException("unable to get DER object", ioe);
        }
        catch (IllegalArgumentException ioe) 
        {
            throw new ASN1ParsingException("unable to get DER object", ioe);
        }
    }
}
