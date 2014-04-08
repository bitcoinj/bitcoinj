package org.bouncycastle.asn1.ess;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.PolicyInformation;

public class SigningCertificateV2
    extends ASN1Object
{
    ASN1Sequence certs;
    ASN1Sequence policies;

    public static SigningCertificateV2 getInstance(
        Object o)
    {
        if (o == null || o instanceof SigningCertificateV2)
        {
            return (SigningCertificateV2) o;
        }
        else if (o instanceof ASN1Sequence)
        {
            return new SigningCertificateV2((ASN1Sequence) o);
        }

        return null;
    }

    private SigningCertificateV2(
        ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        this.certs = ASN1Sequence.getInstance(seq.getObjectAt(0));

        if (seq.size() > 1)
        {
            this.policies = ASN1Sequence.getInstance(seq.getObjectAt(1));
        }
    }

    public SigningCertificateV2(
        ESSCertIDv2 cert)
    {
        this.certs = new DERSequence(cert);
    }

    public SigningCertificateV2(
        ESSCertIDv2[] certs)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i=0; i < certs.length; i++)
        {
            v.add(certs[i]);
        }
        this.certs = new DERSequence(v);
    }

    public SigningCertificateV2(
        ESSCertIDv2[] certs,
        PolicyInformation[] policies)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i=0; i < certs.length; i++)
        {
            v.add(certs[i]);
        }
        this.certs = new DERSequence(v);

        if (policies != null)
        {
            v = new ASN1EncodableVector();
            for (int i=0; i < policies.length; i++)
            {
                v.add(policies[i]);
            }
            this.policies = new DERSequence(v);
        }
    }

    public ESSCertIDv2[] getCerts()
    {
        ESSCertIDv2[] certIds = new ESSCertIDv2[certs.size()];
        for (int i = 0; i != certs.size(); i++)
        {
            certIds[i] = ESSCertIDv2.getInstance(certs.getObjectAt(i));
        }
        return certIds;
    }

    public PolicyInformation[] getPolicies()
    {
        if (policies == null)
        {
            return null;
        }

        PolicyInformation[] policyInformations = new PolicyInformation[policies.size()];
        for (int i = 0; i != policies.size(); i++)
        {
            policyInformations[i] = PolicyInformation.getInstance(policies.getObjectAt(i));
        }
        return policyInformations;
    }

    /**
     * The definition of SigningCertificateV2 is
     * <pre>
     * SigningCertificateV2 ::=  SEQUENCE {
     *      certs        SEQUENCE OF ESSCertIDv2,
     *      policies     SEQUENCE OF PolicyInformation OPTIONAL
     * }
     * </pre>
     * id-aa-signingCertificateV2 OBJECT IDENTIFIER ::= { iso(1)
     *    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
     *    smime(16) id-aa(2) 47 }
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
