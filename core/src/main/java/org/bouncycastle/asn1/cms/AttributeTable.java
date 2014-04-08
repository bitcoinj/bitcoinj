package org.bouncycastle.asn1.cms;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;

/**
 * This is helper tool to construct {@link Attributes} sets.
 */
public class AttributeTable
{
    private Hashtable attributes = new Hashtable();

    public AttributeTable(
        Hashtable  attrs)
    {
        attributes = copyTable(attrs);
    }

    public AttributeTable(
        ASN1EncodableVector v)
    {
        for (int i = 0; i != v.size(); i++)
        {
            Attribute   a = Attribute.getInstance(v.get(i));

            addAttribute(a.getAttrType(), a);
        }
    }

    public AttributeTable(
        ASN1Set    s)
    {
        for (int i = 0; i != s.size(); i++)
        {
            Attribute   a = Attribute.getInstance(s.getObjectAt(i));

            addAttribute(a.getAttrType(), a);
        }
    }

    public AttributeTable(
        Attribute    attr)
    {
        addAttribute(attr.getAttrType(), attr);
    }

    public AttributeTable(
        Attributes    attrs)
    {
        this(ASN1Set.getInstance(attrs.toASN1Primitive()));
    }

    private void addAttribute(
        ASN1ObjectIdentifier oid,
        Attribute           a)
    {
        Object value = attributes.get(oid);
        
        if (value == null)
        {
            attributes.put(oid, a);
        }
        else
        {
            Vector v;
            
            if (value instanceof Attribute)
            {
                v = new Vector();
                
                v.addElement(value);
                v.addElement(a);
            }
            else
            {
                v = (Vector)value;
            
                v.addElement(a);
            }
            
            attributes.put(oid, v);
        }
    }

    /**
     * Return the first attribute matching the OBJECT IDENTIFIER oid.
     * 
     * @param oid type of attribute required.
     * @return first attribute found of type oid.
     */
    public Attribute get(
        ASN1ObjectIdentifier oid)
    {
        Object value = attributes.get(oid);
        
        if (value instanceof Vector)
        {
            return (Attribute)((Vector)value).elementAt(0);
        }
        
        return (Attribute)value;
    }

    /**
     * Return all the attributes matching the OBJECT IDENTIFIER oid. The vector will be 
     * empty if there are no attributes of the required type present.
     * 
     * @param oid type of attribute required.
     * @return a vector of all the attributes found of type oid.
     */
    public ASN1EncodableVector getAll(
        ASN1ObjectIdentifier oid)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        Object value = attributes.get(oid);
        
        if (value instanceof Vector)
        {
            Enumeration e = ((Vector)value).elements();
            
            while (e.hasMoreElements())
            {
                v.add((Attribute)e.nextElement());
            }
        }
        else if (value != null)
        {
            v.add((Attribute)value);
        }
        
        return v;
    }

    public int size()
    {
        int size = 0;

        for (Enumeration en = attributes.elements(); en.hasMoreElements();)
        {
            Object o = en.nextElement();

            if (o instanceof Vector)
            {
                size += ((Vector)o).size();
            }
            else
            {
                size++;
            }
        }

        return size;
    }

    public Hashtable toHashtable()
    {
        return copyTable(attributes);
    }
    
    public ASN1EncodableVector toASN1EncodableVector()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();
        Enumeration          e = attributes.elements();
        
        while (e.hasMoreElements())
        {
            Object value = e.nextElement();
            
            if (value instanceof Vector)
            {
                Enumeration en = ((Vector)value).elements();
                
                while (en.hasMoreElements())
                {
                    v.add(Attribute.getInstance(en.nextElement()));
                }
            }
            else
            {
                v.add(Attribute.getInstance(value));
            }
        }
        
        return v;
    }

    public Attributes toASN1Structure()
    {
        return new Attributes(this.toASN1EncodableVector());
    }

    private Hashtable copyTable(
        Hashtable in)
    {
        Hashtable   out = new Hashtable();
        Enumeration e = in.keys();
        
        while (e.hasMoreElements())
        {
            Object key = e.nextElement();
            
            out.put(key, in.get(key));
        }
        
        return out;
    }

    /**
     * Return a new table with the passed in attribute added.
     *
     * @param attrType
     * @param attrValue
     * @return
     */
    public AttributeTable add(ASN1ObjectIdentifier attrType, ASN1Encodable attrValue)
    {
        AttributeTable newTable = new AttributeTable(attributes);

        newTable.addAttribute(attrType, new Attribute(attrType, new DERSet(attrValue)));

        return newTable;
    }

    public AttributeTable remove(ASN1ObjectIdentifier attrType)
    {
        AttributeTable newTable = new AttributeTable(attributes);

        newTable.attributes.remove(attrType);

        return newTable;
    }
}
