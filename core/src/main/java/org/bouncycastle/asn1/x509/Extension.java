package org.bouncycastle.asn1.x509;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/**
 * an object for the elements in the X.509 V3 extension block.
 */
public class Extension
    extends ASN1Object
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

    private ASN1ObjectIdentifier extnId;
    private boolean             critical;
    private ASN1OctetString      value;

    public Extension(
        ASN1ObjectIdentifier extnId,
        ASN1Boolean critical,
        ASN1OctetString value)
    {
        this(extnId, critical.isTrue(), value);
    }

    public Extension(
        ASN1ObjectIdentifier extnId,
        boolean critical,
        byte[] value)
    {
        this(extnId, critical, new DEROctetString(value));
    }

    public Extension(
        ASN1ObjectIdentifier extnId,
        boolean critical,
        ASN1OctetString value)
    {
        this.extnId = extnId;
        this.critical = critical;
        this.value = value;
    }

    private Extension(ASN1Sequence seq)
    {
        if (seq.size() == 2)
        {
            this.extnId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            this.critical = false;
            this.value = ASN1OctetString.getInstance(seq.getObjectAt(1));
        }
        else if (seq.size() == 3)
        {
            this.extnId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            this.critical = ASN1Boolean.getInstance(seq.getObjectAt(1)).isTrue();
            this.value = ASN1OctetString.getInstance(seq.getObjectAt(2));
        }
        else
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
    }

    public static Extension getInstance(Object obj)
    {
        if (obj instanceof Extension)
        {
            return (Extension)obj;
        }
        else if (obj != null)
        {
            return new Extension(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1ObjectIdentifier getExtnId()
    {
        return extnId;
    }

    public boolean isCritical()
    {
        return critical;
    }

    public ASN1OctetString getExtnValue()
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
            return this.getExtnValue().hashCode() ^ this.getExtnId().hashCode();
        }

        return ~(this.getExtnValue().hashCode() ^ this.getExtnId().hashCode());
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof Extension))
        {
            return false;
        }

        Extension other = (Extension)o;

        return other.getExtnId().equals(this.getExtnId())
            && other.getExtnValue().equals(this.getExtnValue())
            && (other.isCritical() == this.isCritical());
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(extnId);

        if (critical)
        {
            v.add(ASN1Boolean.getInstance(true));
        }

        v.add(value);

        return new DERSequence(v);
    }

    /**
     * Convert the value of the passed in extension to an object
     * @param ext the extension to parse
     * @return the object the value string contains
     * @exception IllegalArgumentException if conversion is not possible
     */
    private static ASN1Primitive convertValueToObject(
        Extension ext)
        throws IllegalArgumentException
    {
        try
        {
            return ASN1Primitive.fromByteArray(ext.getExtnValue().getOctets());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("can't convert extension: " +  e);
        }
    }
}
