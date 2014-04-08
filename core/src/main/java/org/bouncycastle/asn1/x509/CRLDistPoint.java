package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class CRLDistPoint
    extends ASN1Object
{
    ASN1Sequence  seq = null;

    public static CRLDistPoint getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CRLDistPoint getInstance(
        Object  obj)
    {
        if (obj instanceof CRLDistPoint)
        {
            return (CRLDistPoint)obj;
        }
        else if (obj != null)
        {
            return new CRLDistPoint(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private CRLDistPoint(
        ASN1Sequence seq)
    {
        this.seq = seq;
    }
    
    public CRLDistPoint(
        DistributionPoint[] points)
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        for (int i = 0; i != points.length; i++)
        {
            v.add(points[i]);
        }

        seq = new DERSequence(v);
    }

    /**
     * Return the distribution points making up the sequence.
     * 
     * @return DistributionPoint[]
     */
    public DistributionPoint[] getDistributionPoints()
    {
        DistributionPoint[]    dp = new DistributionPoint[seq.size()];
        
        for (int i = 0; i != seq.size(); i++)
        {
            dp[i] = DistributionPoint.getInstance(seq.getObjectAt(i));
        }
        
        return dp;
    }
    
    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * CRLDistPoint ::= SEQUENCE SIZE {1..MAX} OF DistributionPoint
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }

    public String toString()
    {
        StringBuffer buf = new StringBuffer();
        String       sep = System.getProperty("line.separator");

        buf.append("CRLDistPoint:");
        buf.append(sep);
        DistributionPoint dp[] = getDistributionPoints();
        for (int i = 0; i != dp.length; i++)
        {
            buf.append("    ");
            buf.append(dp[i]);
            buf.append(sep);
        }
        return buf.toString();
    }
}
