package org.bouncycastle.asn1.ocsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class Signature
    extends ASN1Object
{
    AlgorithmIdentifier signatureAlgorithm;
    DERBitString        signature;
    ASN1Sequence        certs;

    public Signature(
        AlgorithmIdentifier signatureAlgorithm,
        DERBitString        signature)
    {
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
    }

    public Signature(
        AlgorithmIdentifier signatureAlgorithm,
        DERBitString        signature,
        ASN1Sequence        certs)
    {
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
        this.certs = certs;
    }

    private Signature(
        ASN1Sequence    seq)
    {
        signatureAlgorithm  = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        signature = (DERBitString)seq.getObjectAt(1);

        if (seq.size() == 3)
        {
            certs = ASN1Sequence.getInstance(
                                (ASN1TaggedObject)seq.getObjectAt(2), true);
        }
    }

    public static Signature getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Signature getInstance(
        Object  obj)
    {
        if (obj instanceof Signature)
        {
            return (Signature)obj;
        }
        else if (obj != null)
        {
            return new Signature(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return signatureAlgorithm;
    }

    public DERBitString getSignature()
    {
        return signature;
    }

    public ASN1Sequence getCerts()
    {
        return certs;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * Signature       ::=     SEQUENCE {
     *     signatureAlgorithm      AlgorithmIdentifier,
     *     signature               BIT STRING,
     *     certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL}
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        v.add(signatureAlgorithm);
        v.add(signature);

        if (certs != null)
        {
            v.add(new DERTaggedObject(true, 0, certs));
        }

        return new DERSequence(v);
    }
}
