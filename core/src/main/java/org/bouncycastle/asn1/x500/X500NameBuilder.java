package org.bouncycastle.asn1.x500;

import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;

public class X500NameBuilder
{
    private X500NameStyle template;
    private Vector rdns = new Vector();

    public X500NameBuilder()
    {
        this(BCStyle.INSTANCE);
    }

    public X500NameBuilder(X500NameStyle template)
    {
        this.template = template;
    }

    public X500NameBuilder addRDN(ASN1ObjectIdentifier oid, String value)
    {
        this.addRDN(oid, template.stringToValue(oid, value));

        return this;
    }

    public X500NameBuilder addRDN(ASN1ObjectIdentifier oid, ASN1Encodable value)
    {
        rdns.addElement(new RDN(oid, value));

        return this;
    }

    public X500NameBuilder addRDN(AttributeTypeAndValue attrTAndV)
    {
        rdns.addElement(new RDN(attrTAndV));

        return this;
    }

    public X500NameBuilder addMultiValuedRDN(ASN1ObjectIdentifier[] oids, String[] values)
    {
        ASN1Encodable[] vals = new ASN1Encodable[values.length];

        for (int i = 0; i != vals.length; i++)
        {
            vals[i] = template.stringToValue(oids[i], values[i]);
        }

        return addMultiValuedRDN(oids, vals);
    }

    public X500NameBuilder addMultiValuedRDN(ASN1ObjectIdentifier[] oids, ASN1Encodable[] values)
    {
        AttributeTypeAndValue[] avs = new AttributeTypeAndValue[oids.length];

        for (int i = 0; i != oids.length; i++)
        {
            avs[i] = new AttributeTypeAndValue(oids[i], values[i]);
        }

        return addMultiValuedRDN(avs);
    }

    public X500NameBuilder addMultiValuedRDN(AttributeTypeAndValue[] attrTAndVs)
    {
        rdns.addElement(new RDN(attrTAndVs));

        return this;
    }

    public X500Name build()
    {
        RDN[] vals = new RDN[rdns.size()];

        for (int i = 0; i != vals.length; i++)
        {
            vals[i] = (RDN)rdns.elementAt(i);
        }

        return new X500Name(template, vals);
    }
}
