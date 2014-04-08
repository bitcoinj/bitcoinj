package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * OriginatorPublicKey ::= SEQUENCE {
 *     algorithm AlgorithmIdentifier,
 *     publicKey BIT STRING 
 * }
 * </pre>
 */
public class OriginatorPublicKey
    extends ASN1Object
{
    private AlgorithmIdentifier algorithm;
    private DERBitString        publicKey;
    
    public OriginatorPublicKey(
        AlgorithmIdentifier algorithm,
        byte[]              publicKey)
    {
        this.algorithm = algorithm;
        this.publicKey = new DERBitString(publicKey);
    }

    /**
     * @deprecated use getInstance()
     */
    public OriginatorPublicKey(
        ASN1Sequence seq)
    {
        algorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        publicKey = (DERBitString)seq.getObjectAt(1);
    }
    
    /**
     * Return an OriginatorPublicKey object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static OriginatorPublicKey getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    /**
     * Return an OriginatorPublicKey object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link OriginatorPublicKey} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with OriginatorPublicKey structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static OriginatorPublicKey getInstance(
        Object obj)
    {
        if (obj instanceof OriginatorPublicKey)
        {
            return (OriginatorPublicKey)obj;
        }
        
        if (obj != null)
        {
            return new OriginatorPublicKey(ASN1Sequence.getInstance(obj));
        }

        return null;
    } 

    public AlgorithmIdentifier getAlgorithm()
    {
        return algorithm;
    }

    public DERBitString getPublicKey()
    {
        return publicKey;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(algorithm);
        v.add(publicKey);

        return new DERSequence(v);
    }
}
