package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.2.1">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * RecipientIdentifier ::= CHOICE {
 *     issuerAndSerialNumber IssuerAndSerialNumber,
 *     subjectKeyIdentifier [0] SubjectKeyIdentifier 
 * }
 *
 * SubjectKeyIdentifier ::= OCTET STRING
 * </pre>
 */
public class RecipientIdentifier
    extends ASN1Object
    implements ASN1Choice
{
    private ASN1Encodable id;
    
    public RecipientIdentifier(
        IssuerAndSerialNumber id)
    {
        this.id = id;
    }
    
    public RecipientIdentifier(
        ASN1OctetString id)
    {
        this.id = new DERTaggedObject(false, 0, id);
    }
    
    public RecipientIdentifier(
        ASN1Primitive id)
    {
        this.id = id;
    }
    
    /**
     * Return a RecipientIdentifier object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link RecipientIdentifier} object
     * <li> {@link IssuerAndSerialNumber} object
     * <li> {@link org.bouncycastle.asn1.ASN1OctetString#getInstance(java.lang.Object) ASN1OctetString} input formats (OctetString, byte[]) with value of KeyIdentifier in DER form
     * <li> {@link org.bouncycastle.asn1.ASN1Primitive ASN1Primitive} for RecipientIdentifier constructor
     * </ul>
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static RecipientIdentifier getInstance(
        Object o)
    {
        if (o == null || o instanceof RecipientIdentifier)
        {
            return (RecipientIdentifier)o;
        }
        
        if (o instanceof IssuerAndSerialNumber)
        {
            return new RecipientIdentifier((IssuerAndSerialNumber)o);
        }
        
        if (o instanceof ASN1OctetString)
        {
            return new RecipientIdentifier((ASN1OctetString)o);
        }
        
        if (o instanceof ASN1Primitive)
        {
            return new RecipientIdentifier((ASN1Primitive)o);
        }
        
        throw new IllegalArgumentException(
          "Illegal object in RecipientIdentifier: " + o.getClass().getName());
    } 

    public boolean isTagged()
    {
        return (id instanceof ASN1TaggedObject);
    }

    public ASN1Encodable getId()
    {
        if (id instanceof ASN1TaggedObject)
        {
            return ASN1OctetString.getInstance((ASN1TaggedObject)id, false);
        }

        return IssuerAndSerialNumber.getInstance(id);
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return id.toASN1Primitive();
    }
}
