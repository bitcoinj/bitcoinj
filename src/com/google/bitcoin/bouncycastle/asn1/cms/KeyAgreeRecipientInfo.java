package com.google.bitcoin.bouncycastle.asn1.cms;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1OctetString;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DERInteger;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.DERTaggedObject;
import com.google.bitcoin.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class KeyAgreeRecipientInfo
    extends ASN1Encodable
{
    private DERInteger                  version;
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
        this.version = new DERInteger(3);
        this.originator = originator;
        this.ukm = ukm;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.recipientEncryptedKeys = recipientEncryptedKeys;
    }
    
    public KeyAgreeRecipientInfo(
        ASN1Sequence seq)
    {
        int index = 0;
        
        version = (DERInteger)seq.getObjectAt(index++);
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
     * return a KeyAgreeRecipientInfo object from a tagged object.
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
     * return a KeyAgreeRecipientInfo object from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static KeyAgreeRecipientInfo getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof KeyAgreeRecipientInfo)
        {
            return (KeyAgreeRecipientInfo)obj;
        }
        
        if (obj instanceof ASN1Sequence)
        {
            return new KeyAgreeRecipientInfo((ASN1Sequence)obj);
        }
        
        throw new IllegalArgumentException(
        "Illegal object in KeyAgreeRecipientInfo: " + obj.getClass().getName());

    } 

    public DERInteger getVersion()
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
     * <pre>
     * KeyAgreeRecipientInfo ::= SEQUENCE {
     *     version CMSVersion,  -- always set to 3
     *     originator [0] EXPLICIT OriginatorIdentifierOrKey,
     *     ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
     *     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     *     recipientEncryptedKeys RecipientEncryptedKeys 
     * }
     * </pre>
     */
    public DERObject toASN1Object()
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
