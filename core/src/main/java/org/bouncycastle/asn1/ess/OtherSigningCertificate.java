package org.bouncycastle.asn1.ess;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.PolicyInformation;

public class OtherSigningCertificate
    extends ASN1Object
{
    ASN1Sequence certs;
    ASN1Sequence policies;

    public static OtherSigningCertificate getInstance(Object o)
    {
        if (o instanceof OtherSigningCertificate)
        {
            return (OtherSigningCertificate) o;
        }
        else if (o != null)
        {
            return new OtherSigningCertificate(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * constructeurs
     */
    private OtherSigningCertificate(ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        this.certs = ASN1Sequence.getInstance(seq.getObjectAt(0));

        if (seq.size() > 1)
        {
            this.policies = ASN1Sequence.getInstance(seq.getObjectAt(1));
        }
    }

    public OtherSigningCertificate(
        OtherCertID otherCertID)
    {
        certs = new DERSequence(otherCertID);
    }

    public OtherCertID[] getCerts()
    {
        OtherCertID[] cs = new OtherCertID[certs.size()];

        for (int i = 0; i != certs.size(); i++)
        {
            cs[i] = OtherCertID.getInstance(certs.getObjectAt(i));
        }

        return cs;
    }

    public PolicyInformation[] getPolicies()
    {
        if (policies == null)
        {
            return null;
        }

        PolicyInformation[] ps = new PolicyInformation[policies.size()];

        for (int i = 0; i != policies.size(); i++)
        {
            ps[i] = PolicyInformation.getInstance(policies.getObjectAt(i));
        }

        return ps;
    }

    /**
     * The definition of OtherSigningCertificate is
     * <pre>
     * OtherSigningCertificate ::=  SEQUENCE {
     *      certs        SEQUENCE OF OtherCertID,
     *      policies     SEQUENCE OF PolicyInformation OPTIONAL
     * }
     * </pre>
     * id-aa-ets-otherSigCert OBJECT IDENTIFIER ::= { iso(1)
     *  member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
     *  smime(16) id-aa(2) 19 }
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certs);

        if (policies != null)
        {
            v.add(policies);
        }

        return new DERSequence(v);
    }
}
