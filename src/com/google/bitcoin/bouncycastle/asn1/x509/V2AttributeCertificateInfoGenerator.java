package com.google.bitcoin.bouncycastle.asn1.x509;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.DERBitString;
import com.google.bitcoin.bouncycastle.asn1.DERGeneralizedTime;
import com.google.bitcoin.bouncycastle.asn1.DERInteger;
import com.google.bitcoin.bouncycastle.asn1.DERObjectIdentifier;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.DERSet;

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
    private DERInteger version;
    private Holder holder;
    private AttCertIssuer issuer;
    private AlgorithmIdentifier signature;
    private DERInteger serialNumber;
    private ASN1EncodableVector attributes;
    private DERBitString issuerUniqueID;
    private X509Extensions extensions;

    // Note: validity period start/end dates stored directly
    //private AttCertValidityPeriod attrCertValidityPeriod;
    private DERGeneralizedTime startDate, endDate; 

    public V2AttributeCertificateInfoGenerator()
    {
        this.version = new DERInteger(1);
        attributes = new ASN1EncodableVector();
    }
    
    public void setHolder(Holder holder)
    {
        this.holder = holder;
    }
    
    public void addAttribute(String oid, ASN1Encodable value) 
    {
        attributes.add(new Attribute(new DERObjectIdentifier(oid), new DERSet(value)));
    }

    /**
     * @param attribute
     */
    public void addAttribute(Attribute attribute)
    {
        attributes.add(attribute);
    }
    
    public void setSerialNumber(
        DERInteger  serialNumber)
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
        DERGeneralizedTime startDate)
    {
        this.startDate = startDate;
    }

    public void setEndDate(
        DERGeneralizedTime endDate)
    {
        this.endDate = endDate;
    }

    public void setIssuerUniqueID(
        DERBitString    issuerUniqueID)
    {
        this.issuerUniqueID = issuerUniqueID;
    }

    public void setExtensions(
        X509Extensions    extensions)
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

        return new AttributeCertificateInfo(new DERSequence(v));
    }
}
