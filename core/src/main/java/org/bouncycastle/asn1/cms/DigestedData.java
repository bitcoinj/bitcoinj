package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/** 
 * <a href="http://tools.ietf.org/html/rfc5652#section-7">RFC 5652</a> DigestedData object.
 * <pre>
 * DigestedData ::= SEQUENCE {
 *       version CMSVersion,
 *       digestAlgorithm DigestAlgorithmIdentifier,
 *       encapContentInfo EncapsulatedContentInfo,
 *       digest Digest }
 * </pre>
 */
public class DigestedData
    extends ASN1Object
{
    private ASN1Integer           version;
    private AlgorithmIdentifier  digestAlgorithm;
    private ContentInfo          encapContentInfo;
    private ASN1OctetString      digest;

    public DigestedData(
        AlgorithmIdentifier digestAlgorithm,
        ContentInfo encapContentInfo,
        byte[]      digest)
    {
        this.version = new ASN1Integer(0);
        this.digestAlgorithm = digestAlgorithm;
        this.encapContentInfo = encapContentInfo;
        this.digest = new DEROctetString(digest);
    }

    private DigestedData(
        ASN1Sequence seq)
    {
        this.version = (ASN1Integer)seq.getObjectAt(0);
        this.digestAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.encapContentInfo = ContentInfo.getInstance(seq.getObjectAt(2));
        this.digest = ASN1OctetString.getInstance(seq.getObjectAt(3));
    }

    /**
     * Return a DigestedData object from a tagged object.
     *
     * @param ato the tagged object holding the object we want.
     * @param isExplicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static DigestedData getInstance(
        ASN1TaggedObject ato,
        boolean isExplicit)
    {
        return getInstance(ASN1Sequence.getInstance(ato, isExplicit));
    }
    
    /**
     * Return a DigestedData object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link DigestedData} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DigestedData getInstance(
        Object obj)
    {
        if (obj instanceof DigestedData)
        {
            return (DigestedData)obj;
        }
        
        if (obj != null)
        {
            return new DigestedData(ASN1Sequence.getInstance(obj));
        }
        
        return null;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgorithm;
    }

    public ContentInfo getEncapContentInfo()
    {
        return encapContentInfo;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(digestAlgorithm);
        v.add(encapContentInfo);
        v.add(digest);

        return new BERSequence(v);
    }

    public byte[] getDigest()
    {
        return digest.getOctets();
    }
}
