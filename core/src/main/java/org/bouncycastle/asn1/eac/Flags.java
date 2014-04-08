package org.bouncycastle.asn1.eac;

import java.util.Enumeration;
import java.util.Hashtable;


public class Flags
{

    int value = 0;

    public Flags()
    {

    }

    public Flags(int v)
    {
        value = v;
    }

    public void set(int flag)
    {
        value |= flag;
    }

    public boolean isSet(int flag)
    {
        return (value & flag) != 0;
    }

    public int getFlags()
    {
        return value;
    }

    /* Java 1.5
     String decode(Map<Integer, String> decodeMap)
     {
         StringJoiner joiner = new StringJoiner(" ");
         for (int i : decodeMap.keySet())
         {
             if (isSet(i))
                 joiner.add(decodeMap.get(i));
         }
         return joiner.toString();
     }
     */

    String decode(Hashtable decodeMap)
    {
        StringJoiner joiner = new StringJoiner(" ");
        Enumeration e = decodeMap.keys();
        while (e.hasMoreElements())
        {
            Integer i = (Integer)e.nextElement();
            if (isSet(i.intValue()))
            {
                joiner.add((String)decodeMap.get(i));
            }
        }
        return joiner.toString();
    }

    private class StringJoiner
    {

        String mSeparator;
        boolean First = true;
        StringBuffer b = new StringBuffer();

        public StringJoiner(String separator)
        {
            mSeparator = separator;
        }

        public void add(String str)
        {
            if (First)
            {
                First = false;
            }
            else
            {
                b.append(mSeparator);
            }

            b.append(str);
        }

        public String toString()
        {
            return b.toString();
        }
    }
}
