package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.1">RFC 5652</a> EncryptedContentInfo object.
 *
 * <pre>
 * EncryptedContentInfo ::= SEQUENCE {
 *     contentType ContentType,
 *     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL 
 * }
 * </pre>
 */
public class EncryptedContentInfo
    extends ASN1Object
{
    private ASN1ObjectIdentifier contentType;
    private AlgorithmIdentifier contentEncryptionAlgorithm;
    private ASN1OctetString     encryptedContent;
    
    public EncryptedContentInfo(
        ASN1ObjectIdentifier contentType, 
        AlgorithmIdentifier contentEncryptionAlgorithm,
        ASN1OctetString     encryptedContent)
    {
        this.contentType = contentType;
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
        this.encryptedContent = encryptedContent;
    }
    
    private EncryptedContentInfo(
        ASN1Sequence seq)
    {
        if (seq.size() < 2)
        {
            throw new IllegalArgumentException("Truncated Sequence Found");
        }

        contentType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(
                                                        seq.getObjectAt(1));
        if (seq.size() > 2)
        {
            encryptedContent = ASN1OctetString.getInstance(
                                (ASN1TaggedObject)seq.getObjectAt(2), false);
        }
    }

    /**
     * Return an EncryptedContentInfo object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link EncryptedContentInfo} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static EncryptedContentInfo getInstance(
        Object obj)
    {
        if (obj instanceof EncryptedContentInfo)
        {
            return (EncryptedContentInfo)obj;
        }
        if (obj != null)
        {
            return new EncryptedContentInfo(ASN1Sequence.getInstance(obj));
        }
        
        return null;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    public AlgorithmIdentifier getContentEncryptionAlgorithm()
    {
        return contentEncryptionAlgorithm;
    }

    public ASN1OctetString getEncryptedContent()
    {
        return encryptedContent;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();
        
        v.add(contentType);
        v.add(contentEncryptionAlgorithm);

        if (encryptedContent != null)
        {
            v.add(new BERTaggedObject(false, 0, encryptedContent));
        }
        
        return new BERSequence(v);
    }
}
