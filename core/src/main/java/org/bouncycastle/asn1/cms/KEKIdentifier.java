package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.2.3">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * KEKIdentifier ::= SEQUENCE {
 *     keyIdentifier OCTET STRING,
 *     date GeneralizedTime OPTIONAL,
 *     other OtherKeyAttribute OPTIONAL 
 * }
 * </pre>
 */
public class KEKIdentifier
    extends ASN1Object
{
    private ASN1OctetString    keyIdentifier;
    private ASN1GeneralizedTime date;
    private OtherKeyAttribute  other;
    
    public KEKIdentifier(
        byte[]              keyIdentifier,
        ASN1GeneralizedTime  date,
        OtherKeyAttribute   other)
    {
        this.keyIdentifier = new DEROctetString(keyIdentifier);
        this.date = date;
        this.other = other;
    }
    
    private KEKIdentifier(
        ASN1Sequence seq)
    {
        keyIdentifier = (ASN1OctetString)seq.getObjectAt(0);
        
        switch (seq.size())
        {
        case 1:
            break;
        case 2:
            if (seq.getObjectAt(1) instanceof ASN1GeneralizedTime)
            {
                date = (ASN1GeneralizedTime)seq.getObjectAt(1); 
            }
            else
            {
                other = OtherKeyAttribute.getInstance(seq.getObjectAt(1));
            }
            break;
        case 3:
            date  = (ASN1GeneralizedTime)seq.getObjectAt(1);
            other = OtherKeyAttribute.getInstance(seq.getObjectAt(2));
            break;
        default:
                throw new IllegalArgumentException("Invalid KEKIdentifier");
        }
    }

    /**
     * Return a KEKIdentifier object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static KEKIdentifier getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    /**
     * Return a KEKIdentifier object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link KEKIdentifier} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with KEKIdentifier structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static KEKIdentifier getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof KEKIdentifier)
        {
            return (KEKIdentifier)obj;
        }
        
        if (obj instanceof ASN1Sequence)
        {
            return new KEKIdentifier((ASN1Sequence)obj);
        }
        
        throw new IllegalArgumentException("Invalid KEKIdentifier: " + obj.getClass().getName());
    }

    public ASN1OctetString getKeyIdentifier()
    {
        return keyIdentifier;
    }

    public ASN1GeneralizedTime getDate()
    {
        return date;
    }

    public OtherKeyAttribute getOther()
    {
        return other;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(keyIdentifier);
        
        if (date != null)
        {
            v.add(date);
        }

        if (other != null)
        {
            v.add(other);
        }
        
        return new DERSequence(v);
    }
}
