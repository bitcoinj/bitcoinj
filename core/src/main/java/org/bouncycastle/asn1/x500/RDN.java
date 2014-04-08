package org.bouncycastle.asn1.x500;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;

public class RDN
    extends ASN1Object
{
    private ASN1Set values;

    private RDN(ASN1Set values)
    {
        this.values = values;
    }

    public static RDN getInstance(Object obj)
    {
        if (obj instanceof RDN)
        {
            return (RDN)obj;
        }
        else if (obj != null)
        {
            return new RDN(ASN1Set.getInstance(obj));
        }

        return null;
    }

    /**
     * Create a single valued RDN.
     *
     * @param oid RDN type.
     * @param value RDN value.
     */
    public RDN(ASN1ObjectIdentifier oid, ASN1Encodable value)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(oid);
        v.add(value);

        this.values = new DERSet(new DERSequence(v));
    }

    public RDN(AttributeTypeAndValue attrTAndV)
    {
        this.values = new DERSet(attrTAndV);
    }

    /**
     * Create a multi-valued RDN.
     *
     * @param aAndVs attribute type/value pairs making up the RDN
     */
    public RDN(AttributeTypeAndValue[] aAndVs)
    {
        this.values = new DERSet(aAndVs);
    }

    public boolean isMultiValued()
    {
        return this.values.size() > 1;
    }

    /**
     * Return the number of AttributeTypeAndValue objects in this RDN,
     *
     * @return size of RDN, greater than 1 if multi-valued.
     */
    public int size()
    {
        return this.values.size();
    }

    public AttributeTypeAndValue getFirst()
    {
        if (this.values.size() == 0)
        {
            return null;
        }

        return AttributeTypeAndValue.getInstance(this.values.getObjectAt(0));
    }

    public AttributeTypeAndValue[] getTypesAndValues()
    {
        AttributeTypeAndValue[] tmp = new AttributeTypeAndValue[values.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = AttributeTypeAndValue.getInstance(values.getObjectAt(i));
        }

        return tmp;
    }

    /**
     * <pre>
     * RelativeDistinguishedName ::=
     *                     SET OF AttributeTypeAndValue

     * AttributeTypeAndValue ::= SEQUENCE {
     *        type     AttributeType,
     *        value    AttributeValue }
     * </pre>
     * @return this object as an ASN1Primitive type
     */
    public ASN1Primitive toASN1Primitive()
    {
        return values;
    }
}
