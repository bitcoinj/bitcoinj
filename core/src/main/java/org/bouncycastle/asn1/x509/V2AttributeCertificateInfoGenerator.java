package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;

/**
 * Generator for Version 2 AttributeCertificateInfo
 * <pre>
 * AttributeCertificateInfo ::= SEQUENCE {
 *       version              AttCertVersion -- version is v2,
 *       holder               Holder,
 *       issuer               AttCertIssuer,
 *       signature            AlgorithmIdentifier,
 *       serialNumber         CertificateSerialNumber,
 *       attrCertValidityPeriod   AttCertValidityPeriod,
 *       attributes           SEQUENCE OF Attribute,
 *       issuerUniqueID       UniqueIdentifier OPTIONAL,
 *       extensions           Extensions OPTIONAL
 * }
 * </pre>
 *
 */
public class V2AttributeCertificateInfoGenerator
{
    private ASN1Integer version;
    private Holder holder;
    private AttCertIssuer issuer;
    private AlgorithmIdentifier signature;
    private ASN1Integer serialNumber;
    private ASN1EncodableVector attributes;
    private DERBitString issuerUniqueID;
    private Extensions extensions;

    // Note: validity period start/end dates stored directly
    //private AttCertValidityPeriod attrCertValidityPeriod;
    private ASN1GeneralizedTime startDate, endDate; 

    public V2AttributeCertificateInfoGenerator()
    {
        this.version = new ASN1Integer(1);
        attributes = new ASN1EncodableVector();
    }
    
    public void setHolder(Holder holder)
    {
        this.holder = holder;
    }
    
    public void addAttribute(String oid, ASN1Encodable value) 
    {
        attributes.add(new Attribute(new ASN1ObjectIdentifier(oid), new DERSet(value)));
    }

    /**
     * @param attribute
     */
    public void addAttribute(Attribute attribute)
    {
        attributes.add(attribute);
    }
    
    public void setSerialNumber(
        ASN1Integer  serialNumber)
    {
        this.serialNumber = serialNumber;
    }

    public void setSignature(
        AlgorithmIdentifier    signature)
    {
        this.signature = signature;
    }

    public void setIssuer(
        AttCertIssuer    issuer)
    {
        this.issuer = issuer;
    }

    public void setStartDate(
        ASN1GeneralizedTime startDate)
    {
        this.startDate = startDate;
    }

    public void setEndDate(
        ASN1GeneralizedTime endDate)
    {
        this.endDate = endDate;
    }

    public void setIssuerUniqueID(
        DERBitString    issuerUniqueID)
    {
        this.issuerUniqueID = issuerUniqueID;
    }

    /**
     * @deprecated use method taking Extensions
     * @param extensions
     */
    public void setExtensions(
        X509Extensions    extensions)
    {
        this.extensions = Extensions.getInstance(extensions.toASN1Primitive());
    }

    public void setExtensions(
        Extensions    extensions)
    {
        this.extensions = extensions;
    }

    public AttributeCertificateInfo generateAttributeCertificateInfo()
    {
        if ((serialNumber == null) || (signature == null)
            || (issuer == null) || (startDate == null) || (endDate == null)
            || (holder == null) || (attributes == null))
        {
            throw new IllegalStateException("not all mandatory fields set in V2 AttributeCertificateInfo generator");
        }

        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(version);
        v.add(holder);
        v.add(issuer);
        v.add(signature);
        v.add(serialNumber);
    
        //
        // before and after dates => AttCertValidityPeriod
        //
        AttCertValidityPeriod validity = new AttCertValidityPeriod(startDate, endDate);
        v.add(validity);
        
        // Attributes
        v.add(new DERSequence(attributes));
        
        if (issuerUniqueID != null)
        {
            v.add(issuerUniqueID);
        }
    
        if (extensions != null)
        {
            v.add(extensions);
        }

        return AttributeCertificateInfo.getInstance(new DERSequence(v));
    }
}
