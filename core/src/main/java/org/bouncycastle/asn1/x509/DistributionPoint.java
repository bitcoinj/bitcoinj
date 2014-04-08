package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * The DistributionPoint object.
 * <pre>
 * DistributionPoint ::= SEQUENCE {
 *      distributionPoint [0] DistributionPointName OPTIONAL,
 *      reasons           [1] ReasonFlags OPTIONAL,
 *      cRLIssuer         [2] GeneralNames OPTIONAL
 * }
 * </pre>
 */
public class DistributionPoint
    extends ASN1Object
{
    DistributionPointName       distributionPoint;
    ReasonFlags                 reasons;
    GeneralNames                cRLIssuer;

    public static DistributionPoint getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static DistributionPoint getInstance(
        Object obj)
    {
        if(obj == null || obj instanceof DistributionPoint) 
        {
            return (DistributionPoint)obj;
        }
        
        if(obj instanceof ASN1Sequence) 
        {
            return new DistributionPoint((ASN1Sequence)obj);
        }
        
        throw new IllegalArgumentException("Invalid DistributionPoint: " + obj.getClass().getName());
    }

    public DistributionPoint(
        ASN1Sequence seq)
    {
        for (int i = 0; i != seq.size(); i++)
        {
            ASN1TaggedObject    t = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
            switch (t.getTagNo())
            {
            case 0:
                distributionPoint = DistributionPointName.getInstance(t, true);
                break;
            case 1:
                reasons = new ReasonFlags(DERBitString.getInstance(t, false));
                break;
            case 2:
                cRLIssuer = GeneralNames.getInstance(t, false);
            }
        }
    }
    
    public DistributionPoint(
        DistributionPointName distributionPoint,
        ReasonFlags                 reasons,
        GeneralNames            cRLIssuer)
    {
        this.distributionPoint = distributionPoint;
        this.reasons = reasons;
        this.cRLIssuer = cRLIssuer;
    }
    
    public DistributionPointName getDistributionPoint()
    {
        return distributionPoint;
    }

    public ReasonFlags getReasons()
    {
        return reasons;
    }
    
    public GeneralNames getCRLIssuer()
    {
        return cRLIssuer;
    }
    
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();
        
        if (distributionPoint != null)
        {
            //
            // as this is a CHOICE it must be explicitly tagged
            //
            v.add(new DERTaggedObject(0, distributionPoint));
        }

        if (reasons != null)
        {
            v.add(new DERTaggedObject(false, 1, reasons));
        }

        if (cRLIssuer != null)
        {
            v.add(new DERTaggedObject(false, 2, cRLIssuer));
        }

        return new DERSequence(v);
    }

    public String toString()
    {
        String       sep = System.getProperty("line.separator");
        StringBuffer buf = new StringBuffer();
        buf.append("DistributionPoint: [");
        buf.append(sep);
        if (distributionPoint != null)
        {
            appendObject(buf, sep, "distributionPoint", distributionPoint.toString());
        }
        if (reasons != null)
        {
            appendObject(buf, sep, "reasons", reasons.toString());
        }
        if (cRLIssuer != null)
        {
            appendObject(buf, sep, "cRLIssuer", cRLIssuer.toString());
        }
        buf.append("]");
        buf.append(sep);
        return buf.toString();
    }

    private void appendObject(StringBuffer buf, String sep, String name, String value)
    {
        String       indent = "    ";

        buf.append(indent);
        buf.append(name);
        buf.append(":");
        buf.append(sep);
        buf.append(indent);
        buf.append(indent);
        buf.append(value);
        buf.append(sep);
    }
}
