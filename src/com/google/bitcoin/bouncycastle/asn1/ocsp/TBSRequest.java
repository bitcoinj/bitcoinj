package com.google.bitcoin.bouncycastle.asn1.ocsp;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DERInteger;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.DERTaggedObject;
import com.google.bitcoin.bouncycastle.asn1.x509.GeneralName;
import com.google.bitcoin.bouncycastle.asn1.x509.X509Extensions;

public class TBSRequest
    extends ASN1Encodable
{
    private static final DERInteger V1 = new DERInteger(0);
    
    DERInteger      version;
    GeneralName     requestorName;
    ASN1Sequence    requestList;
    X509Extensions  requestExtensions;

    boolean         versionSet;

    public TBSRequest(
        GeneralName     requestorName,
        ASN1Sequence    requestList,
        X509Extensions  requestExtensions)
    {
        this.version = V1;
        this.requestorName = requestorName;
        this.requestList = requestList;
        this.requestExtensions = requestExtensions;
    }

    public TBSRequest(
        ASN1Sequence    seq)
    {
        int    index = 0;

        if (seq.getObjectAt(0) instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject    o = (ASN1TaggedObject)seq.getObjectAt(0);

            if (o.getTagNo() == 0)
            {
                versionSet = true;
                version = DERInteger.getInstance((ASN1TaggedObject)seq.getObjectAt(0), true);
                index++;
            }
            else
            {
                version = V1;
            }
        }
        else
        {
            version = V1;
        }

        if (seq.getObjectAt(index) instanceof ASN1TaggedObject)
        {
            requestorName = GeneralName.getInstance((ASN1TaggedObject)seq.getObjectAt(index++), true);
        }
        
        requestList = (ASN1Sequence)seq.getObjectAt(index++);

        if (seq.size() == (index + 1))
        {
            requestExtensions = X509Extensions.getInstance((ASN1TaggedObject)seq.getObjectAt(index), true);
        }
    }

    public static TBSRequest getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static TBSRequest getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof TBSRequest)
        {
            return (TBSRequest)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new TBSRequest((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public DERInteger getVersion()
    {
        return version;
    }

    public GeneralName getRequestorName()
    {
        return requestorName;
    }

    public ASN1Sequence getRequestList()
    {
        return requestList;
    }

    public X509Extensions getRequestExtensions()
    {
        return requestExtensions;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * TBSRequest      ::=     SEQUENCE {
     *     version             [0]     EXPLICIT Version DEFAULT v1,
     *     requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
     *     requestList                 SEQUENCE OF Request,
     *     requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        //
        // if default don't include - unless explicitly provided. Not strictly correct
        // but required for some requests
        //
        if (!version.equals(V1) || versionSet)
        {
            v.add(new DERTaggedObject(true, 0, version));
        }
        
        if (requestorName != null)
        {
            v.add(new DERTaggedObject(true, 1, requestorName));
        }

        v.add(requestList);

        if (requestExtensions != null)
        {
            v.add(new DERTaggedObject(true, 2, requestExtensions));
        }

        return new DERSequence(v);
    }
}
