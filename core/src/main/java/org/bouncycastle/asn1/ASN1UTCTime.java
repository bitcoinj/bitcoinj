package org.bouncycastle.asn1;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class ASN1UTCTime
    extends ASN1Primitive
{
    private byte[]      time;

    /**
     * return an UTC Time from the passed in object.
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1UTCTime getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof ASN1UTCTime)
        {
            return (ASN1UTCTime)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1UTCTime)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an UTC Time from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static ASN1UTCTime getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Object o = obj.getObject();

        if (explicit || o instanceof ASN1UTCTime)
        {
            return getInstance(o);
        }
        else
        {
            return new ASN1UTCTime(((ASN1OctetString)o).getOctets());
        }
    }

    /**
     * The correct format for this is YYMMDDHHMMSSZ (it used to be that seconds were
     * never encoded. When you're creating one of these objects from scratch, that's
     * what you want to use, otherwise we'll try to deal with whatever gets read from
     * the input stream... (this is why the input format is different from the getTime()
     * method output).
     * <p>
     *
     * @param time the time string.
     */
    public ASN1UTCTime(
        String time)
    {
        this.time = Strings.toByteArray(time);
        try
        {
            this.getDate();
        }
        catch (ParseException e)
        {
            throw new IllegalArgumentException("invalid date string: " + e.getMessage());
        }
    }

    /**
     * base constructer from a java.util.date object
     */
    public ASN1UTCTime(
        Date time)
    {
        SimpleDateFormat dateF = new SimpleDateFormat("yyMMddHHmmss'Z'");

        dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

        this.time = Strings.toByteArray(dateF.format(time));
    }

    ASN1UTCTime(
        byte[] time)
    {
        this.time = time;
    }

    /**
     * return the time as a date based on whatever a 2 digit year will return. For
     * standardised processing use getAdjustedDate().
     *
     * @return the resulting date
     * @exception ParseException if the date string cannot be parsed.
     */
    public Date getDate()
        throws ParseException
    {
        SimpleDateFormat dateF = new SimpleDateFormat("yyMMddHHmmssz");

        return dateF.parse(getTime());
    }

    /**
     * return the time as an adjusted date
     * in the range of 1950 - 2049.
     *
     * @return a date in the range of 1950 to 2049.
     * @exception ParseException if the date string cannot be parsed.
     */
    public Date getAdjustedDate()
        throws ParseException
    {
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmssz");

        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));

        return dateF.parse(getAdjustedTime());
    }

    /**
     * return the time - always in the form of
     *  YYMMDDhhmmssGMT(+hh:mm|-hh:mm).
     * <p>
     * Normally in a certificate we would expect "Z" rather than "GMT",
     * however adding the "GMT" means we can just use:
     * <pre>
     *     dateF = new SimpleDateFormat("yyMMddHHmmssz");
     * </pre>
     * To read in the time and get a date which is compatible with our local
     * time zone.
     * <p>
     * <b>Note:</b> In some cases, due to the local date processing, this
     * may lead to unexpected results. If you want to stick the normal
     * convention of 1950 to 2049 use the getAdjustedTime() method.
     */
    public String getTime()
    {
        String stime = Strings.fromByteArray(time);

        //
        // standardise the format.
        //
        if (stime.indexOf('-') < 0 && stime.indexOf('+') < 0)
        {
            if (stime.length() == 11)
            {
                return stime.substring(0, 10) + "00GMT+00:00";
            }
            else
            {
                return stime.substring(0, 12) + "GMT+00:00";
            }
        }
        else
        {
            int index = stime.indexOf('-');
            if (index < 0)
            {
                index = stime.indexOf('+');
            }
            String d = stime;

            if (index == stime.length() - 3)
            {
                d += "00";
            }

            if (index == 10)
            {
                return d.substring(0, 10) + "00GMT" + d.substring(10, 13) + ":" + d.substring(13, 15);
            }
            else
            {
                return d.substring(0, 12) + "GMT" + d.substring(12, 15) + ":" +  d.substring(15, 17);
            }
        }
    }

    /**
     * return a time string as an adjusted date with a 4 digit year. This goes
     * in the range of 1950 - 2049.
     */
    public String getAdjustedTime()
    {
        String   d = this.getTime();

        if (d.charAt(0) < '5')
        {
            return "20" + d;
        }
        else
        {
            return "19" + d;
        }
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        int length = time.length;

        return 1 + StreamUtil.calculateBodyLength(length) + length;
    }

    void encode(
        ASN1OutputStream  out)
        throws IOException
    {
        out.write(BERTags.UTC_TIME);

        int length = time.length;

        out.writeLength(length);

        for (int i = 0; i != length; i++)
        {
            out.write((byte)time[i]);
        }
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof ASN1UTCTime))
        {
            return false;
        }

        return Arrays.areEqual(time, ((ASN1UTCTime)o).time);
    }

    public int hashCode()
    {
        return Arrays.hashCode(time);
    }

    public String toString()
    {
      return Strings.fromByteArray(time);
    }
}
