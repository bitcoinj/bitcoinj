package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-10.2.7">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * PasswordRecipientInfo ::= SEQUENCE {
 *     version       CMSVersion,   -- Always set to 0
 *     keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
 *                             OPTIONAL,
 *     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *     encryptedKey  EncryptedKey }
 * </pre>
 */
public class PasswordRecipientInfo
    extends ASN1Object
{
    private ASN1Integer          version;
    private AlgorithmIdentifier keyDerivationAlgorithm;
    private AlgorithmIdentifier keyEncryptionAlgorithm;
    private ASN1OctetString     encryptedKey;

    public PasswordRecipientInfo(
        AlgorithmIdentifier     keyEncryptionAlgorithm,
        ASN1OctetString         encryptedKey)
    {
        this.version = new ASN1Integer(0);
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.encryptedKey = encryptedKey;
    }
    
    public PasswordRecipientInfo(
        AlgorithmIdentifier     keyDerivationAlgorithm,
        AlgorithmIdentifier     keyEncryptionAlgorithm,
        ASN1OctetString         encryptedKey)
    {
        this.version = new ASN1Integer(0);
        this.keyDerivationAlgorithm = keyDerivationAlgorithm;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.encryptedKey = encryptedKey;
    }

    /**
     * @deprecated use getInstance() method.
     */
    public PasswordRecipientInfo(
        ASN1Sequence seq)
    {
        version = (ASN1Integer)seq.getObjectAt(0);
        if (seq.getObjectAt(1) instanceof ASN1TaggedObject)
        {
            keyDerivationAlgorithm = AlgorithmIdentifier.getInstance((ASN1TaggedObject)seq.getObjectAt(1), false);
            keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
            encryptedKey = (ASN1OctetString)seq.getObjectAt(3);
        }
        else
        {
            keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            encryptedKey = (ASN1OctetString)seq.getObjectAt(2);
        }
    }

    /**
     * Return a PasswordRecipientInfo object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static PasswordRecipientInfo getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    /**
     * Return a PasswordRecipientInfo object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link PasswordRecipientInfo} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with PasswordRecipientInfo structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static PasswordRecipientInfo getInstance(
        Object obj)
    {
        if (obj instanceof PasswordRecipientInfo)
        {
            return (PasswordRecipientInfo)obj;
        }
        
        if (obj != null)
        {
            return new PasswordRecipientInfo(ASN1Sequence.getInstance(obj));
        }
        
        return null;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public AlgorithmIdentifier getKeyDerivationAlgorithm()
    {
        return keyDerivationAlgorithm;
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
        
        if (keyDerivationAlgorithm != null)
        {
            v.add(new DERTaggedObject(false, 0, keyDerivationAlgorithm));
        }
        v.add(keyEncryptionAlgorithm);
        v.add(encryptedKey);

        return new DERSequence(v);
    }
}
