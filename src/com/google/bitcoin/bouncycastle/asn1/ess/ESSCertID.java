package com.google.bitcoin.bouncycastle.asn1.ess;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1OctetString;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DEROctetString;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.x509.IssuerSerial;

public class ESSCertID
    extends ASN1Encodable
{
    private ASN1OctetString certHash;

    private IssuerSerial issuerSerial;

    public static ESSCertID getInstance(Object o)
    {
        if (o == null || o instanceof ESSCertID)
        {
            return (ESSCertID)o;
        }
        else if (o instanceof ASN1Sequence)
        {
            return new ESSCertID((ASN1Sequence)o);
        }

        throw new IllegalArgumentException(
                "unknown object in 'ESSCertID' factory : "
                        + o.getClass().getName() + ".");
    }

    /**
     * constructor
     */
    public ESSCertID(ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        certHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
 
        if (seq.size() > 1)
        {
            issuerSerial = IssuerSerial.getInstance(seq.getObjectAt(1));
        }
    }

    public ESSCertID(
        byte[]          hash)
    {
        certHash = new DEROctetString(hash);
    }

    public ESSCertID(
        byte[]          hash,
        IssuerSerial    issuerSerial)
    {
        this.certHash = new DEROctetString(hash);
        this.issuerSerial = issuerSerial;
    }

    public byte[] getCertHash()
    {
        return certHash.getOctets();
    }

    public IssuerSerial getIssuerSerial()
    {
        return issuerSerial;
    }

    /**
     * <pre>
     * ESSCertID ::= SEQUENCE {
     *     certHash Hash, 
     *     issuerSerial IssuerSerial OPTIONAL }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(certHash);
        
        if (issuerSerial != null)
        {
            v.add(issuerSerial);
        }

        return new DERSequence(v);
    }
}
