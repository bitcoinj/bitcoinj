package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;

public class AttributeCertificateInfo
    extends ASN1Object
{
    private ASN1Integer             version;
    private Holder                  holder;
    private AttCertIssuer           issuer;
    private AlgorithmIdentifier     signature;
    private ASN1Integer              serialNumber;
    private AttCertValidityPeriod   attrCertValidityPeriod;
    private ASN1Sequence            attributes;
    private DERBitString            issuerUniqueID;
    private Extensions              extensions;

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
        else if (obj != null)
        {
            return new AttributeCertificateInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private AttributeCertificateInfo(
        ASN1Sequence   seq)
    {
        if (seq.size() < 6 || seq.size() > 9)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        int start;
        if (seq.getObjectAt(0) instanceof ASN1Integer)   // in version 1 certs version is DEFAULT  v1(0)
        {
            this.version = ASN1Integer.getInstance(seq.getObjectAt(0));
            start = 1;
        }
        else
        {
            this.version = new ASN1Integer(0);
            start = 0;
        }

        this.holder = Holder.getInstance(seq.getObjectAt(start));
        this.issuer = AttCertIssuer.getInstance(seq.getObjectAt(start + 1));
        this.signature = AlgorithmIdentifier.getInstance(seq.getObjectAt(start + 2));
        this.serialNumber = ASN1Integer.getInstance(seq.getObjectAt(start + 3));
        this.attrCertValidityPeriod = AttCertValidityPeriod.getInstance(seq.getObjectAt(start + 4));
        this.attributes = ASN1Sequence.getInstance(seq.getObjectAt(start + 5));
        
        for (int i = start + 6; i < seq.size(); i++)
        {
            ASN1Encodable    obj = seq.getObjectAt(i);

            if (obj instanceof DERBitString)
            {
                this.issuerUniqueID = DERBitString.getInstance(seq.getObjectAt(i));
            }
            else if (obj instanceof ASN1Sequence || obj instanceof Extensions)
            {
                this.extensions = Extensions.getInstance(seq.getObjectAt(i));
            }
        }
    }
    
    public ASN1Integer getVersion()
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

    public ASN1Integer getSerialNumber()
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

    public Extensions getExtensions()
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
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        if (version.getValue().intValue() != 0)
        {
            v.add(version);
        }
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
