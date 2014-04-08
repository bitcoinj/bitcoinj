package org.bouncycastle.asn1.esf;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 * OtherRevRefs ::= SEQUENCE {
 *   otherRevRefType OtherRevRefType,
 *   otherRevRefs ANY DEFINED BY otherRevRefType
 * }
 *
 * OtherRevRefType ::= OBJECT IDENTIFIER
 * </pre>
 */
public class OtherRevRefs
    extends ASN1Object
{

    private ASN1ObjectIdentifier otherRevRefType;
    private ASN1Encodable otherRevRefs;

    public static OtherRevRefs getInstance(Object obj)
    {
        if (obj instanceof OtherRevRefs)
        {
            return (OtherRevRefs)obj;
        }
        else if (obj != null)
        {
            return new OtherRevRefs(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private OtherRevRefs(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }
        this.otherRevRefType = new ASN1ObjectIdentifier(((ASN1ObjectIdentifier)seq.getObjectAt(0)).getId());
        try
        {
            this.otherRevRefs = ASN1Primitive.fromByteArray(seq.getObjectAt(1)
                .toASN1Primitive().getEncoded(ASN1Encoding.DER));
        }
        catch (IOException e)
        {
            throw new IllegalStateException();
        }
    }

    public OtherRevRefs(ASN1ObjectIdentifier otherRevRefType, ASN1Encodable otherRevRefs)
    {
        this.otherRevRefType = otherRevRefType;
        this.otherRevRefs = otherRevRefs;
    }

    public ASN1ObjectIdentifier getOtherRevRefType()
    {
        return this.otherRevRefType;
    }

    public ASN1Encodable getOtherRevRefs()
    {
        return this.otherRevRefs;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.otherRevRefType);
        v.add(this.otherRevRefs);
        return new DERSequence(v);
    }
}
