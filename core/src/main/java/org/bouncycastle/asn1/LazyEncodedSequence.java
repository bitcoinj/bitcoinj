package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

/**
 * Note: this class is for processing DER/DL encoded sequences only.
 */
class LazyEncodedSequence
    extends ASN1Sequence
{
    private byte[] encoded;

    LazyEncodedSequence(
        byte[] encoded)
        throws IOException
    {
        this.encoded = encoded;
    }

    private void parse()
    {
        Enumeration en = new LazyConstructionEnumeration(encoded);

        while (en.hasMoreElements())
        {
            seq.addElement(en.nextElement());
        }

        encoded = null;
    }

    public synchronized ASN1Encodable getObjectAt(int index)
    {
        if (encoded != null)
        {
            parse();
        }

        return super.getObjectAt(index);
    }

    public synchronized Enumeration getObjects()
    {
        if (encoded == null)
        {
            return super.getObjects();
        }

        return new LazyConstructionEnumeration(encoded);
    }

    public synchronized int size()
    {
        if (encoded != null)
        {
            parse();
        }

        return super.size();
    }

    ASN1Primitive toDERObject()
    {
        if (encoded != null)
        {
            parse();
        }

        return super.toDERObject();
    }

    ASN1Primitive toDLObject()
    {
        if (encoded != null)
        {
            parse();
        }

        return super.toDLObject();
    }

    int encodedLength()
        throws IOException
    {
        if (encoded != null)
        {
            return 1 + StreamUtil.calculateBodyLength(encoded.length) + encoded.length;
        }
        else
        {
            return super.toDLObject().encodedLength();
        }
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        if (encoded != null)
        {
            out.writeEncoded(BERTags.SEQUENCE | BERTags.CONSTRUCTED, encoded);
        }
        else
        {
            super.toDLObject().encode(out);
        }
    }
}
