package org.bouncycastle.asn1.pkcs;

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
 * @deprecated use RSAPrivateKey
 */
public class RSAPrivateKeyStructure
    extends ASN1Object
{
    private int         version;
    private BigInteger  modulus;
    private BigInteger  publicExponent;
    private BigInteger  privateExponent;
    private BigInteger  prime1;
    private BigInteger  prime2;
    private BigInteger  exponent1;
    private BigInteger  exponent2;
    private BigInteger  coefficient;
    private ASN1Sequence otherPrimeInfos = null;

    public static RSAPrivateKeyStructure getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RSAPrivateKeyStructure getInstance(
        Object  obj)
    {
        if (obj instanceof RSAPrivateKeyStructure)
        {
            return (RSAPrivateKeyStructure)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new RSAPrivateKeyStructure((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }
    
    public RSAPrivateKeyStructure(
        BigInteger  modulus,
        BigInteger  publicExponent,
        BigInteger  privateExponent,
        BigInteger  prime1,
        BigInteger  prime2,
        BigInteger  exponent1,
        BigInteger  exponent2,
        BigInteger  coefficient)
    {
        this.version = 0;
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
        this.prime1 = prime1;
        this.prime2 = prime2;
        this.exponent1 = exponent1;
        this.exponent2 = exponent2;
        this.coefficient = coefficient;
    }

    public RSAPrivateKeyStructure(
        ASN1Sequence  seq)
    {
        Enumeration e = seq.getObjects();

        BigInteger  v = ((ASN1Integer)e.nextElement()).getValue();
        if (v.intValue() != 0 && v.intValue() != 1)
        {
            throw new IllegalArgumentException("wrong version for RSA private key");
        }

        version = v.intValue();
        modulus = ((ASN1Integer)e.nextElement()).getValue();
        publicExponent = ((ASN1Integer)e.nextElement()).getValue();
        privateExponent = ((ASN1Integer)e.nextElement()).getValue();
        prime1 = ((ASN1Integer)e.nextElement()).getValue();
        prime2 = ((ASN1Integer)e.nextElement()).getValue();
        exponent1 = ((ASN1Integer)e.nextElement()).getValue();
        exponent2 = ((ASN1Integer)e.nextElement()).getValue();
        coefficient = ((ASN1Integer)e.nextElement()).getValue();
        
        if (e.hasMoreElements())
        {
            otherPrimeInfos = (ASN1Sequence)e.nextElement();
        }
    }

    public int getVersion()
    {
        return version;
    }
    
    public BigInteger getModulus()
    {
        return modulus;
    }

    public BigInteger getPublicExponent()
    {
        return publicExponent;
    }

    public BigInteger getPrivateExponent()
    {
        return privateExponent;
    }

    public BigInteger getPrime1()
    {
        return prime1;
    }

    public BigInteger getPrime2()
    {
        return prime2;
    }

    public BigInteger getExponent1()
    {
        return exponent1;
    }

    public BigInteger getExponent2()
    {
        return exponent2;
    }

    public BigInteger getCoefficient()
    {
        return coefficient;
    }

    /**
     * This outputs the key in PKCS1v2 format.
     * <pre>
     *      RSAPrivateKey ::= SEQUENCE {
     *                          version Version,
     *                          modulus INTEGER, -- n
     *                          publicExponent INTEGER, -- e
     *                          privateExponent INTEGER, -- d
     *                          prime1 INTEGER, -- p
     *                          prime2 INTEGER, -- q
     *                          exponent1 INTEGER, -- d mod (p-1)
     *                          exponent2 INTEGER, -- d mod (q-1)
     *                          coefficient INTEGER, -- (inverse of q) mod p
     *                          otherPrimeInfos OtherPrimeInfos OPTIONAL
     *                      }
     *
     *      Version ::= INTEGER { two-prime(0), multi(1) }
     *        (CONSTRAINED BY {-- version must be multi if otherPrimeInfos present --})
     * </pre>
     * <p>
     * This routine is written to output PKCS1 version 2.1, private keys.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(new ASN1Integer(version));                       // version
        v.add(new ASN1Integer(getModulus()));
        v.add(new ASN1Integer(getPublicExponent()));
        v.add(new ASN1Integer(getPrivateExponent()));
        v.add(new ASN1Integer(getPrime1()));
        v.add(new ASN1Integer(getPrime2()));
        v.add(new ASN1Integer(getExponent1()));
        v.add(new ASN1Integer(getExponent2()));
        v.add(new ASN1Integer(getCoefficient()));

        if (otherPrimeInfos != null)
        {
            v.add(otherPrimeInfos);
        }
        
        return new DERSequence(v);
    }
}
