package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.2.3">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * KEKRecipientInfo ::= SEQUENCE {
 *     version CMSVersion,  -- always set to 4
 *     kekid KEKIdentifier,
 *     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *     encryptedKey EncryptedKey 
 * }
 * </pre>
 */
public class KEKRecipientInfo
    extends ASN1Object
{
    private ASN1Integer          version;
    private KEKIdentifier       kekid;
    private AlgorithmIdentifier keyEncryptionAlgorithm;
    private ASN1OctetString     encryptedKey;

    public KEKRecipientInfo(
        KEKIdentifier       kekid,
        AlgorithmIdentifier keyEncryptionAlgorithm,
        ASN1OctetString     encryptedKey)
    {
        this.version = new ASN1Integer(4);
        this.kekid = kekid;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.encryptedKey = encryptedKey;
    }
    
    public KEKRecipientInfo(
        ASN1Sequence seq)
    {
        version = (ASN1Integer)seq.getObjectAt(0);
        kekid = KEKIdentifier.getInstance(seq.getObjectAt(1));
        keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
        encryptedKey = (ASN1OctetString)seq.getObjectAt(3);
    }

    /**
     * Return a KEKRecipientInfo object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static KEKRecipientInfo getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    /**
     * Return a KEKRecipientInfo object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link KEKRecipientInfo} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with KEKRecipientInfo structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static KEKRecipientInfo getInstance(
        Object obj)
    {
        if (obj instanceof KEKRecipientInfo)
        {
            return (KEKRecipientInfo)obj;
        }
        
        if (obj != null)
        {
            return new KEKRecipientInfo(ASN1Sequence.getInstance(obj));
        }
        
        return null;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }
    
    public KEKIdentifier getKekid()
    {
        return kekid;
    }

    public AlgorithmIdentifier getKeyEncryptionAlgorithm()
    {
        return keyEncryptionAlgorithm;
    }

    public ASN1OctetString getEncryptedKey()
    {
        return encryptedKey;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(version);
        v.add(kekid);
        v.add(keyEncryptionAlgorithm);
        v.add(encryptedKey);

        return new DERSequence(v);
    }
}
