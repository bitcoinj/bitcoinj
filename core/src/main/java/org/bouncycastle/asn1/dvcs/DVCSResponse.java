package org.bouncycastle.asn1.dvcs;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 *     DVCSResponse ::= CHOICE
 *     {
 *         dvCertInfo         DVCSCertInfo ,
 *         dvErrorNote        [0] DVCSErrorNotice
 *     }
 * </pre>
 */

public class DVCSResponse
    extends ASN1Object
    implements ASN1Choice
{
    private DVCSCertInfo dvCertInfo;
    private DVCSErrorNotice dvErrorNote;

    public DVCSResponse(DVCSCertInfo dvCertInfo)
    {
        this.dvCertInfo = dvCertInfo;
    }

    public DVCSResponse(DVCSErrorNotice dvErrorNote)
    {
        this.dvErrorNote = dvErrorNote;
    }

    public static DVCSResponse getInstance(Object obj)
    {
        if (obj == null || obj instanceof DVCSResponse)
        {
            return (DVCSResponse)obj;
        }
        else
        {
            if (obj instanceof byte[])
            {
                try
                {
                    return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
                }
                catch (IOException e)
                {
                    throw new IllegalArgumentException("failed to construct sequence from byte[]: " + e.getMessage());
                }
            }
            if (obj instanceof ASN1Sequence)
            {
                DVCSCertInfo dvCertInfo = DVCSCertInfo.getInstance(obj);

                return new DVCSResponse(dvCertInfo);
            }
            if (obj instanceof ASN1TaggedObject)
            {
                ASN1TaggedObject t = ASN1TaggedObject.getInstance(obj);
                DVCSErrorNotice dvErrorNote = DVCSErrorNotice.getInstance(t, false);

                return new DVCSResponse(dvErrorNote);
            }
        }

        throw new IllegalArgumentException("Couldn't convert from object to DVCSResponse: " + obj.getClass().getName());
    }

    public static DVCSResponse getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public DVCSCertInfo getCertInfo()
    {
        return dvCertInfo;
    }

    public DVCSErrorNotice getErrorNotice()
    {
        return dvErrorNote;
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (dvCertInfo != null)
        {
            return dvCertInfo.toASN1Primitive();
        }
        else
        {
            return new DERTaggedObject(0, dvErrorNote);
        }
    }

    public String toString()
    {
        if (dvCertInfo != null)
        {
            return "DVCSResponse {\ndvCertInfo: " + dvCertInfo.toString() + "}\n";
        }
        if (dvErrorNote != null)
        {
            return "DVCSResponse {\ndvErrorNote: " + dvErrorNote.toString() + "}\n";
        }
        return null;
    }
}
