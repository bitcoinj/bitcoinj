package org.bouncycastle.asn1;

import java.util.Enumeration;
import java.util.Vector;

public class ASN1EncodableVector
{
    Vector v = new Vector();

    public ASN1EncodableVector()
    {
    }

    public void add(ASN1Encodable obj)
    {
        v.addElement(obj);
    }

    public void addAll(ASN1EncodableVector other)
    {
        for (Enumeration en = other.v.elements(); en.hasMoreElements();)
        {
            v.addElement(en.nextElement());
        }
    }

    public ASN1Encodable get(int i)
    {
        return (ASN1Encodable)v.elementAt(i);
    }

    public int size()
    {
        return v.size();
    }
}
