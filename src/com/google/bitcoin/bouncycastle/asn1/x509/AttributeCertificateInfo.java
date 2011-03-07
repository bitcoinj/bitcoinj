package com.google.bitcoin.bouncycastle.asn1.x509;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DERBitString;
import com.google.bitcoin.bouncycastle.asn1.DERInteger;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;

public class AttributeCertificateInfo
    extends ASN1Encodable
{
    private DERInteger              version;
    private Holder                  holder;
    private AttCertIssuer           issuer;
    private AlgorithmIdentifier     signature;
    private DERInteger              serialNumber;
    private AttCertValidityPeriod   attrCertValidityPeriod;
    private ASN1Sequence            attributes;
    private DERBitString            issuerUniqueID;
    private X509Extensions          extensions;

    public static AttributeCertificateInfo getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static AttributeCertificateInfo getInstance(
        Object  obj)
    {
        if (obj instanceof AttributeCertificateInfo)
        {
            return (AttributeCertificateInfo)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new AttributeCertificateInfo((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public AttributeCertificateInfo(
        ASN1Sequence   seq)
    {
        if (seq.size() < 7 || seq.size() > 9)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        this.version = DERInteger.getInstance(seq.getObjectAt(0));
        this.holder = Holder.getInstance(seq.getObjectAt(1));
        this.issuer = AttCertIssuer.getInstance(seq.getObjectAt(2));
        this.signature = AlgorithmIdentifier.getInstance(seq.getObjectAt(3));
        this.serialNumber = DERInteger.getInstance(seq.getObjectAt(4));
        this.attrCertValidityPeriod = AttCertValidityPeriod.getInstance(seq.getObjectAt(5));
        this.attributes = ASN1Sequence.getInstance(seq.getObjectAt(6));
        
        for (int i = 7; i < seq.size(); i++)
        {
            ASN1Encodable    obj = (ASN1Encodable)seq.getObjectAt(i);

            if (obj instanceof DERBitString)
            {
                this.issuerUniqueID = DERBitString.getInstance(seq.getObjectAt(i));
            }
            else if (obj instanceof ASN1Sequence || obj instanceof X509Extensions)
            {
                this.extensions = X509Extensions.getInstance(seq.getObjectAt(i));
            }
        }
    }
    
    public DERInteger getVersion()
    {
        return version;
    }

    public Holder getHolder()
    {
        return holder;
    }

    public AttCertIssuer getIssuer()
    {
        return issuer;
    }

    public AlgorithmIdentifier getSignature()
    {
        return signature;
    }

    public DERInteger getSerialNumber()
    {
        return serialNumber;
    }

    public AttCertValidityPeriod getAttrCertValidityPeriod()
    {
        return attrCertValidityPeriod;
    }

    public ASN1Sequence getAttributes()
    {
        return attributes;
    }

    public DERBitString getIssuerUniqueID()
    {
        return issuerUniqueID;
    }

    public X509Extensions getExtensions()
    {
        return extensions;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  AttributeCertificateInfo ::= SEQUENCE {
     *       version              AttCertVersion -- version is v2,
     *       holder               Holder,
     *       issuer               AttCertIssuer,
     *       signature            AlgorithmIdentifier,
     *       serialNumber         CertificateSerialNumber,
     *       attrCertValidityPeriod   AttCertValidityPeriod,
     *       attributes           SEQUENCE OF Attribute,
     *       issuerUniqueID       UniqueIdentifier OPTIONAL,
     *       extensions           Extensions OPTIONAL
     *  }
     *
     *  AttCertVersion ::= INTEGER { v2(1) }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(version);
        v.add(holder);
        v.add(issuer);
        v.add(signature);
        v.add(serialNumber);
        v.add(attrCertValidityPeriod);
        v.add(attributes);
        
        if (issuerUniqueID != null)
        {
            v.add(issuerUniqueID);
        }
        
        if (extensions != null)
        {
            v.add(extensions);
        }
        
        return new DERSequence(v);
    }
}
