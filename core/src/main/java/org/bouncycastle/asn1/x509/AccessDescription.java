package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * The AccessDescription object.
 * <pre>
 * AccessDescription  ::=  SEQUENCE {
 *       accessMethod          OBJECT IDENTIFIER,
 *       accessLocation        GeneralName  }
 * </pre>
 */
public class AccessDescription
    extends ASN1Object
{
    public final static ASN1ObjectIdentifier id_ad_caIssuers = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.2");
    
    public final static ASN1ObjectIdentifier id_ad_ocsp = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1");
        
    ASN1ObjectIdentifier accessMethod = null;
    GeneralName accessLocation = null;

    public static AccessDescription getInstance(
        Object  obj)
    {
        if (obj instanceof AccessDescription)
        {
            return (AccessDescription)obj;
        }
        else if (obj != null)
        {
            return new AccessDescription(ASN1Sequence.getInstance(obj));
        }

        return null;
    }
 
    private AccessDescription(
        ASN1Sequence   seq)
    {
        if (seq.size() != 2) 
        {
            throw new IllegalArgumentException("wrong number of elements in sequence");
        }
        
        accessMethod = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        accessLocation = GeneralName.getInstance(seq.getObjectAt(1));
    }

    /**
     * create an AccessDescription with the oid and location provided.
     */
    public AccessDescription(
        ASN1ObjectIdentifier oid,
        GeneralName location)
    {
        accessMethod = oid;
        accessLocation = location;
    }

    /**
     * 
     * @return the access method.
     */
    public ASN1ObjectIdentifier getAccessMethod()
    {
        return accessMethod;
    }
    
    /**
     * 
     * @return the access location
     */
    public GeneralName getAccessLocation()
    {
        return accessLocation;
    }
    
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector accessDescription  = new ASN1EncodableVector();
        
        accessDescription.add(accessMethod);
        accessDescription.add(accessLocation);

        return new DERSequence(accessDescription);
    }

    public String toString()
    {
        return ("AccessDescription: Oid(" + this.accessMethod.getId() + ")");
    }
}
