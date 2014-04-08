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
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.2.1">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * KeyTransRecipientInfo ::= SEQUENCE {
 *     version CMSVersion,  -- always set to 0 or 2
 *     rid RecipientIdentifier,
 *     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *     encryptedKey EncryptedKey 
 * }
 * </pre>
 */
public class KeyTransRecipientInfo
    extends ASN1Object
{
    private ASN1Integer          version;
    private RecipientIdentifier rid;
    private AlgorithmIdentifier keyEncryptionAlgorithm;
    private ASN1OctetString     encryptedKey;

    public KeyTransRecipientInfo(
        RecipientIdentifier rid,
        AlgorithmIdentifier keyEncryptionAlgorithm,
        ASN1OctetString     encryptedKey)
    {
        if (rid.toASN1Primitive() instanceof ASN1TaggedObject)
        {
            this.version = new ASN1Integer(2);
        }
        else
        {
            this.version = new ASN1Integer(0);
        }

        this.rid = rid;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.encryptedKey = encryptedKey;
    }

    /**
     * @deprecated use getInstance()
     */
    public KeyTransRecipientInfo(
        ASN1Sequence seq)
    {
        this.version = (ASN1Integer)seq.getObjectAt(0);
        this.rid = RecipientIdentifier.getInstance(seq.getObjectAt(1));
        this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
        this.encryptedKey = (ASN1OctetString)seq.getObjectAt(3);
    }

    /**
     * Return a KeyTransRecipientInfo object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link KeyTransRecipientInfo} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with KeyTransRecipientInfo structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static KeyTransRecipientInfo getInstance(
        Object obj)
    {
        if (obj instanceof KeyTransRecipientInfo)
        {
            return (KeyTransRecipientInfo)obj;
        }
        
        if(obj != null)
        {
            return new KeyTransRecipientInfo(ASN1Sequence.getInstance(obj));
        }
        
        return null;
    } 

    public ASN1Integer getVersion()
    {
        return version;
    }

    public RecipientIdentifier getRecipientIdentifier()
    {
        return rid;
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
        v.add(rid);
        v.add(keyEncryptionAlgorithm);
        v.add(encryptedKey);

        return new DERSequence(v);
    }
}
