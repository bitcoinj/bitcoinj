package org.bouncycastle.asn1.ess;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class ContentHints
    extends ASN1Object
{
    private DERUTF8String contentDescription;
    private ASN1ObjectIdentifier contentType;

    public static ContentHints getInstance(Object o)
    {
        if (o instanceof ContentHints)
        {
            return (ContentHints)o;
        }
        else if (o != null)
        {
            return new ContentHints(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * constructor
     */
    private ContentHints(ASN1Sequence seq)
    {
        ASN1Encodable field = seq.getObjectAt(0);
        if (field.toASN1Primitive() instanceof DERUTF8String)
        {
            contentDescription = DERUTF8String.getInstance(field);
            contentType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
        }
        else
        {
            contentType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        }
    }

    public ContentHints(
        ASN1ObjectIdentifier contentType)
    {
        this.contentType = contentType;
        this.contentDescription = null;
    }

    public ContentHints(
        ASN1ObjectIdentifier contentType,
        DERUTF8String contentDescription)
    {
        this.contentType = contentType;
        this.contentDescription = contentDescription;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    public DERUTF8String getContentDescription()
    {
        return contentDescription;
    }

    /**
     * <pre>
     * ContentHints ::= SEQUENCE {
     *   contentDescription UTF8String (SIZE (1..MAX)) OPTIONAL,
     *   contentType ContentType }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (contentDescription != null)
        {
            v.add(contentDescription);
        }

        v.add(contentType);

        return new DERSequence(v);
    }
}
