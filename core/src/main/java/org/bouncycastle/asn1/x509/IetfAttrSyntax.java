package org.bouncycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Implementation of <code>IetfAttrSyntax</code> as specified by RFC3281.
 */
public class IetfAttrSyntax
    extends ASN1Object
{
    public static final int VALUE_OCTETS    = 1;
    public static final int VALUE_OID       = 2;
    public static final int VALUE_UTF8      = 3;
    GeneralNames            policyAuthority = null;
    Vector                  values          = new Vector();
    int                     valueChoice     = -1;

    public static IetfAttrSyntax getInstance(Object obj)
    {
        if (obj instanceof IetfAttrSyntax)
        {
            return (IetfAttrSyntax)obj;
        }
        if (obj != null)
        {
            return new IetfAttrSyntax(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     *  
     */
    private IetfAttrSyntax(ASN1Sequence seq)
    {
        int i = 0;

        if (seq.getObjectAt(0) instanceof ASN1TaggedObject)
        {
            policyAuthority = GeneralNames.getInstance(((ASN1TaggedObject)seq.getObjectAt(0)), false);
            i++;
        }
        else if (seq.size() == 2)
        { // VOMS fix
            policyAuthority = GeneralNames.getInstance(seq.getObjectAt(0));
            i++;
        }

        if (!(seq.getObjectAt(i) instanceof ASN1Sequence))
        {
            throw new IllegalArgumentException("Non-IetfAttrSyntax encoding");
        }

        seq = (ASN1Sequence)seq.getObjectAt(i);

        for (Enumeration e = seq.getObjects(); e.hasMoreElements();)
        {
            ASN1Primitive obj = (ASN1Primitive)e.nextElement();
            int type;

            if (obj instanceof ASN1ObjectIdentifier)
            {
                type = VALUE_OID;
            }
            else if (obj instanceof DERUTF8String)
            {
                type = VALUE_UTF8;
            }
            else if (obj instanceof DEROctetString)
            {
                type = VALUE_OCTETS;
            }
            else
            {
                throw new IllegalArgumentException("Bad value type encoding IetfAttrSyntax");
            }

            if (valueChoice < 0)
            {
                valueChoice = type;
            }

            if (type != valueChoice)
            {
                throw new IllegalArgumentException("Mix of value types in IetfAttrSyntax");
            }

            values.addElement(obj);
        }
    }

    public GeneralNames getPolicyAuthority()
    {
        return policyAuthority;
    }

    public int getValueType()
    {
        return valueChoice;
    }

    public Object[] getValues()
    {
        if (this.getValueType() == VALUE_OCTETS)
        {
            ASN1OctetString[] tmp = new ASN1OctetString[values.size()];
            
            for (int i = 0; i != tmp.length; i++)
            {
                tmp[i] = (ASN1OctetString)values.elementAt(i);
            }
            
            return tmp;
        }
        else if (this.getValueType() == VALUE_OID)
        {
            ASN1ObjectIdentifier[] tmp = new ASN1ObjectIdentifier[values.size()];
            
            for (int i = 0; i != tmp.length; i++)
            {
                tmp[i] = (ASN1ObjectIdentifier)values.elementAt(i);
            }
            
            return tmp;
        }
        else
        {
            DERUTF8String[] tmp = new DERUTF8String[values.size()];
            
            for (int i = 0; i != tmp.length; i++)
            {
                tmp[i] = (DERUTF8String)values.elementAt(i);
            }
            
            return tmp;
        }
    }

    /**
     * 
     * <pre>
     * 
     *  IetfAttrSyntax ::= SEQUENCE {
     *    policyAuthority [0] GeneralNames OPTIONAL,
     *    values SEQUENCE OF CHOICE {
     *      octets OCTET STRING,
     *      oid OBJECT IDENTIFIER,
     *      string UTF8String
     *    }
     *  }
     *  
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (policyAuthority != null)
        {
            v.add(new DERTaggedObject(0, policyAuthority));
        }

        ASN1EncodableVector v2 = new ASN1EncodableVector();

        for (Enumeration i = values.elements(); i.hasMoreElements();)
        {
            v2.add((ASN1Encodable)i.nextElement());
        }

        v.add(new DERSequence(v2));

        return new DERSequence(v);
    }
}
