package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-5.3">RFC 5652</a>:
 * Identify who signed the containing {@link SignerInfo} object.
 * <p>
 * The certificates referred to by this are at containing {@link SignedData} structure.
 * <p>
 * <pre>
 * SignerIdentifier ::= CHOICE {
 *     issuerAndSerialNumber IssuerAndSerialNumber,
 *     subjectKeyIdentifier [0] SubjectKeyIdentifier 
 * }
 *
 * SubjectKeyIdentifier ::= OCTET STRING
 * </pre>
 */
public class SignerIdentifier
    extends ASN1Object
    implements ASN1Choice
{
    private ASN1Encodable id;
    
    public SignerIdentifier(
        IssuerAndSerialNumber id)
    {
        this.id = id;
    }
    
    public SignerIdentifier(
        ASN1OctetString id)
    {
        this.id = new DERTaggedObject(false, 0, id);
    }
    
    public SignerIdentifier(
        ASN1Primitive id)
    {
        this.id = id;
    }
    
    /**
     * Return a SignerIdentifier object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link SignerIdentifier} object
     * <li> {@link IssuerAndSerialNumber} object
     * <li> {@link org.bouncycastle.asn1.ASN1OctetString#getInstance(java.lang.Object) ASN1OctetString} input formats with SignerIdentifier structure inside
     * <li> {@link org.bouncycastle.asn1.ASN1Primitive ASN1Primitive} for SignerIdentifier constructor.
     * </ul>
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static SignerIdentifier getInstance(
        Object o)
    {
        if (o == null || o instanceof SignerIdentifier)
        {
            return (SignerIdentifier)o;
        }
        
        if (o instanceof IssuerAndSerialNumber)
        {
            return new SignerIdentifier((IssuerAndSerialNumber)o);
        }
        
        if (o instanceof ASN1OctetString)
        {
            return new SignerIdentifier((ASN1OctetString)o);
        }
        
        if (o instanceof ASN1Primitive)
        {
            return new SignerIdentifier((ASN1Primitive)o);
        }
        
        throw new IllegalArgumentException(
             "Illegal object in SignerIdentifier: " + o.getClass().getName());
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

        return id;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return id.toASN1Primitive();
    }
}
