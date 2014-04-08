package org.bouncycastle.asn1.dvcs;

import java.util.Date;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;

/**
 * <pre>
 *     DVCSTime ::= CHOICE  {
 *         genTime                      GeneralizedTime,
 *         timeStampToken               ContentInfo
 *     }
 * </pre>
 */
public class DVCSTime
    extends ASN1Object
    implements ASN1Choice
{
    private ASN1GeneralizedTime genTime;
    private ContentInfo timeStampToken;
    private Date time;

    // constructors:

    public DVCSTime(Date time)
    {
        this(new ASN1GeneralizedTime(time));
    }

    public DVCSTime(ASN1GeneralizedTime genTime)
    {
        this.genTime = genTime;
    }

    public DVCSTime(ContentInfo timeStampToken)
    {
        this.timeStampToken = timeStampToken;
    }

    public static DVCSTime getInstance(Object obj)
    {
        if (obj instanceof DVCSTime)
        {
            return (DVCSTime)obj;
        }
        else if (obj instanceof ASN1GeneralizedTime)
        {
            return new DVCSTime(ASN1GeneralizedTime.getInstance(obj));
        }
        else if (obj != null)
        {
            return new DVCSTime(ContentInfo.getInstance(obj));
        }

        return null;
    }

    public static DVCSTime getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(obj.getObject()); // must be explicitly tagged
    }


    // selectors:

    public ASN1GeneralizedTime getGenTime()
    {
        return genTime;
    }

    public ContentInfo getTimeStampToken()
    {
        return timeStampToken;
    }

    public ASN1Primitive toASN1Primitive()
    {

        if (genTime != null)
        {
            return genTime;
        }

        if (timeStampToken != null)
        {
            return timeStampToken.toASN1Primitive();
        }

        return null;
    }

    public String toString()
    {
        if (genTime != null)
        {
            return genTime.toString();
        }
        if (timeStampToken != null)
        {
            return timeStampToken.toString();
        }
        return null;
    }
}
