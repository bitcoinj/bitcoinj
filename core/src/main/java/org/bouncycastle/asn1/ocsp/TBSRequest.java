package org.bouncycastle.asn1.ocsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extensions;

public class TBSRequest
    extends ASN1Object
{
    private static final ASN1Integer V1 = new ASN1Integer(0);
    
    ASN1Integer      version;
    GeneralName     requestorName;
    ASN1Sequence    requestList;
    Extensions  requestExtensions;

    boolean         versionSet;

    /**
     * @deprecated use method taking Extensions
     * @param requestorName
     * @param requestList
     * @param requestExtensions
     */
    public TBSRequest(
        GeneralName     requestorName,
        ASN1Sequence    requestList,
        X509Extensions requestExtensions)
    {
        this.version = V1;
        this.requestorName = requestorName;
        this.requestList = requestList;
        this.requestExtensions = Extensions.getInstance(requestExtensions);
    }

    public TBSRequest(
        GeneralName     requestorName,
        ASN1Sequence    requestList,
        Extensions  requestExtensions)
    {
        this.version = V1;
        this.requestorName = requestorName;
        this.requestList = requestList;
        this.requestExtensions = requestExtensions;
    }

    private TBSRequest(
        ASN1Sequence    seq)
    {
        int    index = 0;

        if (seq.getObjectAt(0) instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject    o = (ASN1TaggedObject)seq.getObjectAt(0);

            if (o.getTagNo() == 0)
            {
                versionSet = true;
                version = ASN1Integer.getInstance((ASN1TaggedObject)seq.getObjectAt(0), true);
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
            requestExtensions = Extensions.getInstance((ASN1TaggedObject)seq.getObjectAt(index), true);
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
        if (obj instanceof TBSRequest)
        {
            return (TBSRequest)obj;
        }
        else if (obj != null)
        {
            return new TBSRequest(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1Integer getVersion()
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

    public Extensions getRequestExtensions()
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
    public ASN1Primitive toASN1Primitive()
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
