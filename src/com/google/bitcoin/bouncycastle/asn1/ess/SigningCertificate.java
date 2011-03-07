package com.google.bitcoin.bouncycastle.asn1.ess;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.x509.PolicyInformation;


public class SigningCertificate
    extends ASN1Encodable
{
    ASN1Sequence certs;
    ASN1Sequence policies;

    public static SigningCertificate getInstance(Object o)
    {
        if (o == null || o instanceof SigningCertificate)
        {
            return (SigningCertificate) o;
        }
        else if (o instanceof ASN1Sequence)
        {
            return new SigningCertificate((ASN1Sequence) o);
        }

        throw new IllegalArgumentException(
                "unknown object in 'SigningCertificate' factory : "
                        + o.getClass().getName() + ".");
    }

    /**
     * constructeurs
     */
    public SigningCertificate(ASN1Sequence seq)
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

    public SigningCertificate(
        ESSCertID essCertID)
    {
        certs = new DERSequence(essCertID);
    }

    public ESSCertID[] getCerts()
    {
        ESSCertID[] cs = new ESSCertID[certs.size()];
        
        for (int i = 0; i != certs.size(); i++)
        {
            cs[i] = ESSCertID.getInstance(certs.getObjectAt(i));
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
     * The definition of SigningCertificate is
     * <pre>
     * SigningCertificate ::=  SEQUENCE {
     *      certs        SEQUENCE OF ESSCertID,
     *      policies     SEQUENCE OF PolicyInformation OPTIONAL
     * }
     * </pre>
     * id-aa-signingCertificate OBJECT IDENTIFIER ::= { iso(1)
     *  member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
     *  smime(16) id-aa(2) 12 }
     */
    public DERObject toASN1Object()
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
