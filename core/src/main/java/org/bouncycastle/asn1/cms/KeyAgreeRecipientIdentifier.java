package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * KeyAgreeRecipientIdentifier ::= CHOICE {
 *     issuerAndSerialNumber IssuerAndSerialNumber,
 *     rKeyId [0] IMPLICIT RecipientKeyIdentifier }
 * </pre>
 */
public class KeyAgreeRecipientIdentifier
    extends ASN1Object
    implements ASN1Choice
{
    private IssuerAndSerialNumber issuerSerial;
    private RecipientKeyIdentifier rKeyID;

    /**
     * Return an KeyAgreeRecipientIdentifier object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static KeyAgreeRecipientIdentifier getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    /**
     * Return an KeyAgreeRecipientIdentifier object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> {@link KeyAgreeRecipientIdentifier} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with IssuerAndSerialNumber structure inside
     * <li> {@link org.bouncycastle.asn1.ASN1TaggedObject#getInstance(java.lang.Object) ASN1TaggedObject} with tag value 0: a KeyAgreeRecipientIdentifier data structure
     * </ul>
     * <p>
     * Note: no byte[] input!
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static KeyAgreeRecipientIdentifier getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof KeyAgreeRecipientIdentifier)
        {
            return (KeyAgreeRecipientIdentifier)obj;
        }
        
        if (obj instanceof ASN1Sequence)
        {
            return new KeyAgreeRecipientIdentifier(IssuerAndSerialNumber.getInstance(obj));
        }
        
        if (obj instanceof ASN1TaggedObject && ((ASN1TaggedObject)obj).getTagNo() == 0)
        {
            return new KeyAgreeRecipientIdentifier(RecipientKeyIdentifier.getInstance(
                (ASN1TaggedObject)obj, false));
        }
        
        throw new IllegalArgumentException("Invalid KeyAgreeRecipientIdentifier: " + obj.getClass().getName());
    } 

    public KeyAgreeRecipientIdentifier(
        IssuerAndSerialNumber issuerSerial)
    {
        this.issuerSerial = issuerSerial;
        this.rKeyID = null;
    }

    public KeyAgreeRecipientIdentifier(
         RecipientKeyIdentifier rKeyID)
    {
        this.issuerSerial = null;
        this.rKeyID = rKeyID;
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber()
    {
        return issuerSerial;
    }

    public RecipientKeyIdentifier getRKeyID()
    {
        return rKeyID;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        if (issuerSerial != null)
        {
            return issuerSerial.toASN1Primitive();
        }

        return new DERTaggedObject(false, 0, rKeyID);
    }
}
