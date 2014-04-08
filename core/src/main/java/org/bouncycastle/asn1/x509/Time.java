package org.bouncycastle.asn1.x509;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERUTCTime;

public class Time
    extends ASN1Object
    implements ASN1Choice
{
    ASN1Primitive time;

    public static Time getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(obj.getObject()); // must be explicitly tagged
    }

    public Time(
        ASN1Primitive   time)
    {
        if (!(time instanceof ASN1UTCTime)
            && !(time instanceof ASN1GeneralizedTime))
        {
            throw new IllegalArgumentException("unknown object passed to Time");
        }

        this.time = time; 
    }

    /**
     * creates a time object from a given date - if the date is between 1950
     * and 2049 a UTCTime object is generated, otherwise a GeneralizedTime
     * is used.
     */
    public Time(
        Date    date)
    {
        SimpleTimeZone      tz = new SimpleTimeZone(0, "Z");
        SimpleDateFormat    dateF = new SimpleDateFormat("yyyyMMddHHmmss");

        dateF.setTimeZone(tz);

        String  d = dateF.format(date) + "Z";
        int     year = Integer.parseInt(d.substring(0, 4));

        if (year < 1950 || year > 2049)
        {
            time = new DERGeneralizedTime(d);
        }
        else
        {
            time = new DERUTCTime(d.substring(2));
        }
    }

    public static Time getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof Time)
        {
            return (Time)obj;
        }
        else if (obj instanceof ASN1UTCTime)
        {
            return new Time((ASN1UTCTime)obj);
        }
        else if (obj instanceof ASN1GeneralizedTime)
        {
            return new Time((ASN1GeneralizedTime)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public String getTime()
    {
        if (time instanceof ASN1UTCTime)
        {
            return ((ASN1UTCTime)time).getAdjustedTime();
        }
        else
        {
            return ((ASN1GeneralizedTime)time).getTime();
        }
    }

    public Date getDate()
    {
        try
        {
            if (time instanceof ASN1UTCTime)
            {
                return ((ASN1UTCTime)time).getAdjustedDate();
            }
            else
            {
                return ((ASN1GeneralizedTime)time).getDate();
            }
        }
        catch (ParseException e)
        {         // this should never happen
            throw new IllegalStateException("invalid date string: " + e.getMessage());
        }
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * Time ::= CHOICE {
     *             utcTime        UTCTime,
     *             generalTime    GeneralizedTime }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return time;
    }

    public String toString()
    {
        return getTime();
    }
}
