package org.bouncycastle.asn1.x509;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * an object for the elements in the X.509 V3 extension block.
 * @deprecated use Extension
 */
public class X509Extension
{
    /**
     * Subject Directory Attributes
     */
    public static final ASN1ObjectIdentifier subjectDirectoryAttributes = new ASN1ObjectIdentifier("2.5.29.9");
    
    /**
     * Subject Key Identifier 
     */
    public static final ASN1ObjectIdentifier subjectKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.14");

    /**
     * Key Usage 
     */
    public static final ASN1ObjectIdentifier keyUsage = new ASN1ObjectIdentifier("2.5.29.15");

    /**
     * Private Key Usage Period 
     */
    public static final ASN1ObjectIdentifier privateKeyUsagePeriod = new ASN1ObjectIdentifier("2.5.29.16");

    /**
     * Subject Alternative Name 
     */
    public static final ASN1ObjectIdentifier subjectAlternativeName = new ASN1ObjectIdentifier("2.5.29.17");

    /**
     * Issuer Alternative Name 
     */
    public static final ASN1ObjectIdentifier issuerAlternativeName = new ASN1ObjectIdentifier("2.5.29.18");

    /**
     * Basic Constraints 
     */
    public static final ASN1ObjectIdentifier basicConstraints = new ASN1ObjectIdentifier("2.5.29.19");

    /**
     * CRL Number 
     */
    public static final ASN1ObjectIdentifier cRLNumber = new ASN1ObjectIdentifier("2.5.29.20");

    /**
     * Reason code 
     */
    public static final ASN1ObjectIdentifier reasonCode = new ASN1ObjectIdentifier("2.5.29.21");

    /**
     * Hold Instruction Code 
     */
    public static final ASN1ObjectIdentifier instructionCode = new ASN1ObjectIdentifier("2.5.29.23");

    /**
     * Invalidity Date 
     */
    public static final ASN1ObjectIdentifier invalidityDate = new ASN1ObjectIdentifier("2.5.29.24");

    /**
     * Delta CRL indicator 
     */
    public static final ASN1ObjectIdentifier deltaCRLIndicator = new ASN1ObjectIdentifier("2.5.29.27");

    /**
     * Issuing Distribution Point 
     */
    public static final ASN1ObjectIdentifier issuingDistributionPoint = new ASN1ObjectIdentifier("2.5.29.28");

    /**
     * Certificate Issuer 
     */
    public static final ASN1ObjectIdentifier certificateIssuer = new ASN1ObjectIdentifier("2.5.29.29");

    /**
     * Name Constraints 
     */
    public static final ASN1ObjectIdentifier nameConstraints = new ASN1ObjectIdentifier("2.5.29.30");

    /**
     * CRL Distribution Points 
     */
    public static final ASN1ObjectIdentifier cRLDistributionPoints = new ASN1ObjectIdentifier("2.5.29.31");

    /**
     * Certificate Policies 
     */
    public static final ASN1ObjectIdentifier certificatePolicies = new ASN1ObjectIdentifier("2.5.29.32");

    /**
     * Policy Mappings 
     */
    public static final ASN1ObjectIdentifier policyMappings = new ASN1ObjectIdentifier("2.5.29.33");

    /**
     * Authority Key Identifier 
     */
    public static final ASN1ObjectIdentifier authorityKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.35");

    /**
     * Policy Constraints 
     */
    public static final ASN1ObjectIdentifier policyConstraints = new ASN1ObjectIdentifier("2.5.29.36");

    /**
     * Extended Key Usage 
     */
    public static final ASN1ObjectIdentifier extendedKeyUsage = new ASN1ObjectIdentifier("2.5.29.37");

    /**
     * Freshest CRL
     */
    public static final ASN1ObjectIdentifier freshestCRL = new ASN1ObjectIdentifier("2.5.29.46");
     
    /**
     * Inhibit Any Policy
     */
    public static final ASN1ObjectIdentifier inhibitAnyPolicy = new ASN1ObjectIdentifier("2.5.29.54");

    /**
     * Authority Info Access
     */
    public static final ASN1ObjectIdentifier authorityInfoAccess = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.1");

    /**
     * Subject Info Access
     */
    public static final ASN1ObjectIdentifier subjectInfoAccess = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.11");
    
    /**
     * Logo Type
     */
    public static final ASN1ObjectIdentifier logoType = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.12");

    /**
     * BiometricInfo
     */
    public static final ASN1ObjectIdentifier biometricInfo = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.2");
    
    /**
     * QCStatements
     */
    public static final ASN1ObjectIdentifier qCStatements = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3");

    /**
     * Audit identity extension in attribute certificates.
     */
    public static final ASN1ObjectIdentifier auditIdentity = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.4");
    
    /**
     * NoRevAvail extension in attribute certificates.
     */
    public static final ASN1ObjectIdentifier noRevAvail = new ASN1ObjectIdentifier("2.5.29.56");

    /**
     * TargetInformation extension in attribute certificates.
     */
    public static final ASN1ObjectIdentifier targetInformation = new ASN1ObjectIdentifier("2.5.29.55");
        
    boolean             critical;
    ASN1OctetString     value;

    public X509Extension(
        ASN1Boolean             critical,
        ASN1OctetString         value)
    {
        this.critical = critical.isTrue();
        this.value = value;
    }

    public X509Extension(
        boolean                 critical,
        ASN1OctetString         value)
    {
        this.critical = critical;
        this.value = value;
    }

    public boolean isCritical()
    {
        return critical;
    }

    public ASN1OctetString getValue()
    {
        return value;
    }

    public ASN1Encodable getParsedValue()
    {
        return convertValueToObject(this);
    }

    public int hashCode()
    {
        if (this.isCritical())
        {
            return this.getValue().hashCode();
        }

        return ~this.getValue().hashCode();
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof X509Extension))
        {
            return false;
        }

        X509Extension   other = (X509Extension)o;

        return other.getValue().equals(this.getValue())
            && (other.isCritical() == this.isCritical());
    }

    /**
     * Convert the value of the passed in extension to an object
     * @param ext the extension to parse
     * @return the object the value string contains
     * @exception IllegalArgumentException if conversion is not possible
     */
    public static ASN1Primitive convertValueToObject(
        X509Extension ext)
        throws IllegalArgumentException
    {
        try
        {
            return ASN1Primitive.fromByteArray(ext.getValue().getOctets());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("can't convert extension: " +  e);
        }
    }
}
