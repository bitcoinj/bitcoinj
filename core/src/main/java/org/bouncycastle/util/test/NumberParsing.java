package org.bouncycastle.util.test;

/**
 * Parsing
 */
public final class NumberParsing
{
    private NumberParsing() 
    {
        // Hide constructor
    }
    
    public static long decodeLongFromHex(String longAsString) 
    {
        if ((longAsString.charAt(1) == 'x')
            || (longAsString.charAt(1) == 'X'))
        {
            return Long.parseLong(longAsString.substring(2), 16);
        }

        return Long.parseLong(longAsString, 16);
    }
    
    public static int decodeIntFromHex(String intAsString)
    {
        if ((intAsString.charAt(1) == 'x')
            || (intAsString.charAt(1) == 'X'))
        {
            return Integer.parseInt(intAsString.substring(2), 16);
        }

        return Integer.parseInt(intAsString, 16);
    }
}
