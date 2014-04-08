package org.bouncycastle.asn1.pkcs;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DLSequence;

public class ContentInfo
    extends ASN1Object
    implements PKCSObjectIdentifiers
{
    private ASN1ObjectIdentifier contentType;
    private ASN1Encodable content;
    private boolean       isBer = true;

    public static ContentInfo getInstance(
        Object  obj)
    {
        if (obj instanceof ContentInfo)
        {
            return (ContentInfo)obj;
        }

        if (obj != null)
        {
            return new ContentInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private ContentInfo(
        ASN1Sequence  seq)
    {
        Enumeration   e = seq.getObjects();

        contentType = (ASN1ObjectIdentifier)e.nextElement();

        if (e.hasMoreElements())
        {
            content = ((ASN1TaggedObject)e.nextElement()).getObject();
        }

        isBer = seq instanceof BERSequence;
    }

    public ContentInfo(
        ASN1ObjectIdentifier contentType,
        ASN1Encodable content)
    {
        this.contentType = contentType;
        this.content = content;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    public ASN1Encodable getContent()
    {
        return content;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * ContentInfo ::= SEQUENCE {
     *          contentType ContentType,
     *          content
     *          [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(contentType);

        if (content != null)
        {
            v.add(new BERTaggedObject(true, 0, content));
        }

        if (isBer)
        {
            return new BERSequence(v);
        }
        else
        {
            return new DLSequence(v);
        }
    }
}
