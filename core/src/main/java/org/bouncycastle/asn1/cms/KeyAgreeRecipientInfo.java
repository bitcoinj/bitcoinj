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
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * KeyAgreeRecipientInfo ::= SEQUENCE {
 *     version CMSVersion,  -- always set to 3
 *     originator [0] EXPLICIT OriginatorIdentifierOrKey,
 *     ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
 *     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *     recipientEncryptedKeys RecipientEncryptedKeys 
 * }
 *
 * UserKeyingMaterial ::= OCTET STRING
 * </pre>
 */
public class KeyAgreeRecipientInfo
    extends ASN1Object
{
    private ASN1Integer                  version;
    private OriginatorIdentifierOrKey   originator;
    private ASN1OctetString             ukm;
    private AlgorithmIdentifier         keyEncryptionAlgorithm;
    private ASN1Sequence                recipientEncryptedKeys;
    
    public KeyAgreeRecipientInfo(
        OriginatorIdentifierOrKey   originator,
        ASN1OctetString             ukm,
        AlgorithmIdentifier         keyEncryptionAlgorithm,
        ASN1Sequence                recipientEncryptedKeys)
    {
        this.version = new ASN1Integer(3);
        this.originator = originator;
        this.ukm = ukm;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.recipientEncryptedKeys = recipientEncryptedKeys;
    }

    /**
     * @deprecated use getInstance()
     */
    public KeyAgreeRecipientInfo(
        ASN1Sequence seq)
    {
        int index = 0;
        
        version = (ASN1Integer)seq.getObjectAt(index++);
        originator = OriginatorIdentifierOrKey.getInstance(
                            (ASN1TaggedObject)seq.getObjectAt(index++), true);

        if (seq.getObjectAt(index) instanceof ASN1TaggedObject)
        {
            ukm = ASN1OctetString.getInstance(
                            (ASN1TaggedObject)seq.getObjectAt(index++), true);
        }

        keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(
                                                seq.getObjectAt(index++));

        recipientEncryptedKeys = (ASN1Sequence)seq.getObjectAt(index++);
    }
    
    /**
     * Return a KeyAgreeRecipientInfo object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static KeyAgreeRecipientInfo getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    /**
     * Return a KeyAgreeRecipientInfo object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link KeyAgreeRecipientInfo} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with KeyAgreeRecipientInfo structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static KeyAgreeRecipientInfo getInstance(
        Object obj)
    {
        if (obj instanceof KeyAgreeRecipientInfo)
        {
            return (KeyAgreeRecipientInfo)obj;
        }
        
        if (obj != null)
        {
            return new KeyAgreeRecipientInfo(ASN1Sequence.getInstance(obj));
        }
        
        return null;
    } 

    public ASN1Integer getVersion()
    {
        return version;
    }

    public OriginatorIdentifierOrKey getOriginator()
    {
        return originator;
    }

    public ASN1OctetString getUserKeyingMaterial()
    {
        return ukm;
    }

    public AlgorithmIdentifier getKeyEncryptionAlgorithm()
    {
        return keyEncryptionAlgorithm;
    }

    public ASN1Sequence getRecipientEncryptedKeys()
    {
        return recipientEncryptedKeys;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(version);
        v.add(new DERTaggedObject(true, 0, originator));
        
        if (ukm != null)
        {
            v.add(new DERTaggedObject(true, 1, ukm));
        }
        
        v.add(keyEncryptionAlgorithm);
        v.add(recipientEncryptedKeys);

        return new DERSequence(v);
    }
}
