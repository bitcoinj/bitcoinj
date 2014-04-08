package org.bouncycastle.asn1.x509;

import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * @deprecated use org.bouncycastle.asn1.pkcs.RSAPublicKey
 */
public class RSAPublicKeyStructure
    extends ASN1Object
{
    private BigInteger  modulus;
    private BigInteger  publicExponent;

    public static RSAPublicKeyStructure getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RSAPublicKeyStructure getInstance(
        Object obj)
    {
        if(obj == null || obj instanceof RSAPublicKeyStructure) 
        {
            return (RSAPublicKeyStructure)obj;
        }
        
        if(obj instanceof ASN1Sequence) 
        {
            return new RSAPublicKeyStructure((ASN1Sequence)obj);
        }
        
        throw new IllegalArgumentException("Invalid RSAPublicKeyStructure: " + obj.getClass().getName());
    }
    
    public RSAPublicKeyStructure(
        BigInteger  modulus,
        BigInteger  publicExponent)
    {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
    }

    public RSAPublicKeyStructure(
        ASN1Sequence  seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        Enumeration e = seq.getObjects();

        modulus = ASN1Integer.getInstance(e.nextElement()).getPositiveValue();
        publicExponent = ASN1Integer.getInstance(e.nextElement()).getPositiveValue();
    }

    public BigInteger getModulus()
    {
        return modulus;
    }

    public BigInteger getPublicExponent()
    {
        return publicExponent;
    }

    /**
     * This outputs the key in PKCS1v2 format.
     * <pre>
     *      RSAPublicKey ::= SEQUENCE {
     *                          modulus INTEGER, -- n
     *                          publicExponent INTEGER, -- e
     *                      }
     * </pre>
     * <p>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(new ASN1Integer(getModulus()));
        v.add(new ASN1Integer(getPublicExponent()));

        return new DERSequence(v);
    }
}
