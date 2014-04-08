package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <a href="http://tools.ietf.org/html/rfc5940">RFC 5940</a>:
 * Additional Cryptographic Message Syntax (CMS) Revocation Information Choices.
 * <p>
 * <pre>
 * SCVPReqRes ::= SEQUENCE {
 *     request  [0] EXPLICIT ContentInfo OPTIONAL,
 *     response     ContentInfo }
 * </pre>
 */
public class SCVPReqRes
    extends ASN1Object
{
    private final ContentInfo request;
    private final ContentInfo response;

    /**
     * Return a SCVPReqRes object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link SCVPReqRes} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with SCVPReqRes structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static SCVPReqRes getInstance(
        Object  obj)
    {
        if (obj instanceof SCVPReqRes)
        {
            return (SCVPReqRes)obj;
        }
        else if (obj != null)
        {
            return new SCVPReqRes(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private SCVPReqRes(
        ASN1Sequence seq)
    {
        if (seq.getObjectAt(0) instanceof ASN1TaggedObject)
        {
            this.request = ContentInfo.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(0)), true);
            this.response = ContentInfo.getInstance(seq.getObjectAt(1));
        }
        else
        {
            this.request = null;
            this.response = ContentInfo.getInstance(seq.getObjectAt(0));
        }
    }

    public SCVPReqRes(ContentInfo response)
    {
        this.request = null;       // use of this confuses earlier JDKs
        this.response = response;
    }

    public SCVPReqRes(ContentInfo request, ContentInfo response)
    {
        this.request = request;
        this.response = response;
    }

    public ContentInfo getRequest()
    {
        return request;
    }

    public ContentInfo getResponse()
    {
        return response;
    }

    /**
     * @return  the ASN.1 primitive representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        if (request != null)
        {
            v.add(new DERTaggedObject(true, 0, request));
        }

        v.add(response);

        return new DERSequence(v);
    }
}
