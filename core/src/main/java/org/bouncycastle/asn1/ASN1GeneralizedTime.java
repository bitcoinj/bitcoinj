package org.bouncycastle.asn1;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class ASN1GeneralizedTime
    extends ASN1Primitive
{
    private byte[]      time;

       /**
        * return a generalized time from the passed in object
        *
        * @exception IllegalArgumentException if the object cannot be converted.
        */
       public static ASN1GeneralizedTime getInstance(
           Object  obj)
       {
           if (obj == null || obj instanceof ASN1GeneralizedTime)
           {
               return (ASN1GeneralizedTime)obj;
           }

           if (obj instanceof byte[])
           {
               try
               {
                   return (ASN1GeneralizedTime)fromByteArray((byte[])obj);
               }
               catch (Exception e)
               {
                   throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
               }
           }

           throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
       }

       /**
        * return a Generalized Time object from a tagged object.
        *
        * @param obj the tagged object holding the object we want
        * @param explicit true if the object is meant to be explicitly
        *              tagged false otherwise.
        * @exception IllegalArgumentException if the tagged object cannot
        *               be converted.
        */
       public static ASN1GeneralizedTime getInstance(
           ASN1TaggedObject obj,
           boolean          explicit)
       {
           ASN1Primitive o = obj.getObject();

           if (explicit || o instanceof ASN1GeneralizedTime)
           {
               return getInstance(o);
           }
           else
           {
               return new ASN1GeneralizedTime(((ASN1OctetString)o).getOctets());
           }
       }

       /**
        * The correct format for this is YYYYMMDDHHMMSS[.f]Z, or without the Z
        * for local time, or Z+-HHMM on the end, for difference between local
        * time and UTC time. The fractional second amount f must consist of at
        * least one number with trailing zeroes removed.
        *
        * @param time the time string.
        * @exception IllegalArgumentException if String is an illegal format.
        */
       public ASN1GeneralizedTime(
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
        * base constructor from a java.util.date object
        */
       public ASN1GeneralizedTime(
           Date time)
       {
           SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");

           dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

           this.time = Strings.toByteArray(dateF.format(time));
       }

       ASN1GeneralizedTime(
           byte[] bytes)
       {
           this.time = bytes;
       }

       /**
        * Return the time.
        * @return The time string as it appeared in the encoded object.
        */
       public String getTimeString()
       {
           return Strings.fromByteArray(time);
       }

       /**
        * return the time - always in the form of
        *  YYYYMMDDhhmmssGMT(+hh:mm|-hh:mm).
        * <p>
        * Normally in a certificate we would expect "Z" rather than "GMT",
        * however adding the "GMT" means we can just use:
        * <pre>
        *     dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
        * </pre>
        * To read in the time and get a date which is compatible with our local
        * time zone.
        */
       public String getTime()
       {
           String stime = Strings.fromByteArray(time);

           //
           // standardise the format.
           //
           if (stime.charAt(stime.length() - 1) == 'Z')
           {
               return stime.substring(0, stime.length() - 1) + "GMT+00:00";
           }
           else
           {
               int signPos = stime.length() - 5;
               char sign = stime.charAt(signPos);
               if (sign == '-' || sign == '+')
               {
                   return stime.substring(0, signPos)
                       + "GMT"
                       + stime.substring(signPos, signPos + 3)
                       + ":"
                       + stime.substring(signPos + 3);
               }
               else
               {
                   signPos = stime.length() - 3;
                   sign = stime.charAt(signPos);
                   if (sign == '-' || sign == '+')
                   {
                       return stime.substring(0, signPos)
                           + "GMT"
                           + stime.substring(signPos)
                           + ":00";
                   }
               }
           }
           return stime + calculateGMTOffset();
       }

       private String calculateGMTOffset()
       {
           String sign = "+";
           TimeZone timeZone = TimeZone.getDefault();
           int offset = timeZone.getRawOffset();
           if (offset < 0)
           {
               sign = "-";
               offset = -offset;
           }
           int hours = offset / (60 * 60 * 1000);
           int minutes = (offset - (hours * 60 * 60 * 1000)) / (60 * 1000);

           try
           {
               if (timeZone.useDaylightTime() && timeZone.inDaylightTime(this.getDate()))
               {
                   hours += sign.equals("+") ? 1 : -1;
               }
           }
           catch (ParseException e)
           {
               // we'll do our best and ignore daylight savings
           }

           return "GMT" + sign + convert(hours) + ":" + convert(minutes);
       }

       private String convert(int time)
       {
           if (time < 10)
           {
               return "0" + time;
           }

           return Integer.toString(time);
       }

       public Date getDate()
           throws ParseException
       {
           SimpleDateFormat dateF;
           String stime = Strings.fromByteArray(time);
           String d = stime;

           if (stime.endsWith("Z"))
           {
               if (hasFractionalSeconds())
               {
                   dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
               }
               else
               {
                   dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
               }

               dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
           }
           else if (stime.indexOf('-') > 0 || stime.indexOf('+') > 0)
           {
               d = this.getTime();
               if (hasFractionalSeconds())
               {
                   dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSSz");
               }
               else
               {
                   dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
               }

               dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
           }
           else
           {
               if (hasFractionalSeconds())
               {
                   dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS");
               }
               else
               {
                   dateF = new SimpleDateFormat("yyyyMMddHHmmss");
               }

               dateF.setTimeZone(new SimpleTimeZone(0, TimeZone.getDefault().getID()));
           }

           if (hasFractionalSeconds())
           {
               // java misinterprets extra digits as being milliseconds...
               String frac = d.substring(14);
               int    index;
               for (index = 1; index < frac.length(); index++)
               {
                   char ch = frac.charAt(index);
                   if (!('0' <= ch && ch <= '9'))
                   {
                       break;
                   }
               }

               if (index - 1 > 3)
               {
                   frac = frac.substring(0, 4) + frac.substring(index);
                   d = d.substring(0, 14) + frac;
               }
               else if (index - 1 == 1)
               {
                   frac = frac.substring(0, index) + "00" + frac.substring(index);
                   d = d.substring(0, 14) + frac;
               }
               else if (index - 1 == 2)
               {
                   frac = frac.substring(0, index) + "0" + frac.substring(index);
                   d = d.substring(0, 14) + frac;
               }
           }

           return dateF.parse(d);
       }

       private boolean hasFractionalSeconds()
       {
           for (int i = 0; i != time.length; i++)
           {
               if (time[i] == '.')
               {
                   if (i == 14)
                   {
                       return true;
                   }
               }
           }
           return false;
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
           out.writeEncoded(BERTags.GENERALIZED_TIME, time);
       }

       boolean asn1Equals(
           ASN1Primitive  o)
       {
           if (!(o instanceof ASN1GeneralizedTime))
           {
               return false;
           }

           return Arrays.areEqual(time, ((ASN1GeneralizedTime)o).time);
       }

       public int hashCode()
       {
           return Arrays.hashCode(time);
       }
}
