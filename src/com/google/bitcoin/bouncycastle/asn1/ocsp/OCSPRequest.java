package com.google.bitcoin.bouncycastle.asn1.ocsp;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.DERTaggedObject;

public class OCSPRequest
    extends ASN1Encodable
{
    TBSRequest      tbsRequest;
    Signature       optionalSignature;

    public OCSPRequest(
        TBSRequest  tbsRequest,
        Signature   optionalSignature)
    {
        this.tbsRequest = tbsRequest;
        this.optionalSignature = optionalSignature;
    }

    public OCSPRequest(
        ASN1Sequence    seq)
    {
        tbsRequest = TBSRequest.getInstance(seq.getObjectAt(0));

        if (seq.size() == 2)
        {
            optionalSignature = Signature.getInstance(
                                (ASN1TaggedObject)seq.getObjectAt(1), true);
        }
    }
    
    public static OCSPRequest getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OCSPRequest getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof OCSPRequest)
        {
            return (OCSPRequest)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new OCSPRequest((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }
    
    public TBSRequest getTbsRequest()
    {
        return tbsRequest;
    }

    public Signature getOptionalSignature()
    {
        return optionalSignature;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * OCSPRequest     ::=     SEQUENCE {
     *     tbsRequest                  TBSRequest,
     *     optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        v.add(tbsRequest);

        if (optionalSignature != null)
        {
            v.add(new DERTaggedObject(true, 0, optionalSignature));
        }

        return new DERSequence(v);
    }
}
