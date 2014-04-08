package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-8">RFC 5652</a> EncryptedData object.
 * <p>
 * <pre>
 * EncryptedData ::= SEQUENCE {
 *     version CMSVersion,
 *     encryptedContentInfo EncryptedContentInfo,
 *     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
 * </pre>
 */
public class EncryptedData
    extends ASN1Object
{
    private ASN1Integer version;
    private EncryptedContentInfo encryptedContentInfo;
    private ASN1Set unprotectedAttrs;

    /**
     * Return an EncryptedData object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link EncryptedData} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats
     * </ul>
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static EncryptedData getInstance(Object o)
    {
        if (o instanceof EncryptedData)
        {
            return (EncryptedData)o;
        }

        if (o != null)
        {
            return new EncryptedData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public EncryptedData(EncryptedContentInfo encInfo)
    {
        this(encInfo,  null);
    }

    public EncryptedData(EncryptedContentInfo encInfo, ASN1Set unprotectedAttrs)
    {
        this.version = new ASN1Integer((unprotectedAttrs == null) ? 0 : 2);
        this.encryptedContentInfo = encInfo;
        this.unprotectedAttrs = unprotectedAttrs;
    }

    private EncryptedData(ASN1Sequence seq)
    {
        this.version = ASN1Integer.getInstance(seq.getObjectAt(0));
        this.encryptedContentInfo = EncryptedContentInfo.getInstance(seq.getObjectAt(1));

        if (seq.size() == 3)
        {
            this.unprotectedAttrs = ASN1Set.getInstance(seq.getObjectAt(2));
        }
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public EncryptedContentInfo getEncryptedContentInfo()
    {
        return encryptedContentInfo;
    }

    public ASN1Set getUnprotectedAttrs()
    {
        return unprotectedAttrs;
    }

    /**
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(encryptedContentInfo);
        if (unprotectedAttrs != null)
        {
            v.add(new BERTaggedObject(false, 1, unprotectedAttrs));
        }

        return new BERSequence(v);
    }
}
