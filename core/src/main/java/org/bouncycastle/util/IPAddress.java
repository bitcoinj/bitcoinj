package org.bouncycastle.util;

public class IPAddress
{
    /**
     * Validate the given IPv4 or IPv6 address.
     *
     * @param address the IP address as a String.
     *
     * @return true if a valid address, false otherwise
     */
    public static boolean isValid(
        String address)
    {
        return isValidIPv4(address) || isValidIPv6(address);
    }

    /**
     * Validate the given IPv4 or IPv6 address and netmask.
     *
     * @param address the IP address as a String.
     *
     * @return true if a valid address with netmask, false otherwise
     */
    public static boolean isValidWithNetMask(
        String address)
    {
        return isValidIPv4WithNetmask(address) || isValidIPv6WithNetmask(address);
    }

    /**
     * Validate the given IPv4 address.
     * 
     * @param address the IP address as a String.
     *
     * @return true if a valid IPv4 address, false otherwise
     */
    public static boolean isValidIPv4(
        String address)
    {
        if (address.length() == 0)
        {
            return false;
        }

        int octet;
        int octets = 0;
        
        String temp = address+".";

        int pos;
        int start = 0;
        while (start < temp.length()
            && (pos = temp.indexOf('.', start)) > start)
        {
            if (octets == 4)
            {
                return false;
            }
            try
            {
                octet = Integer.parseInt(temp.substring(start, pos));
            }
            catch (NumberFormatException ex)
            {
                return false;
            }
            if (octet < 0 || octet > 255)
            {
                return false;
            }
            start = pos + 1;
            octets++;
        }

        return octets == 4;
    }

    public static boolean isValidIPv4WithNetmask(
        String address)
    {
        int index = address.indexOf("/");
        String mask = address.substring(index + 1);

        return (index > 0) && isValidIPv4(address.substring(0, index))
                           && (isValidIPv4(mask) || isMaskValue(mask, 32));
    }

    public static boolean isValidIPv6WithNetmask(
        String address)
    {
        int index = address.indexOf("/");
        String mask = address.substring(index + 1);

        return (index > 0) && (isValidIPv6(address.substring(0, index))
                           && (isValidIPv6(mask) || isMaskValue(mask, 128)));
    }

    private static boolean isMaskValue(String component, int size)
    {
        try
        {
            int value = Integer.parseInt(component);

            return value >= 0 && value <= size;
        }
        catch (NumberFormatException e)
        {
            return false;
        }
    }

    /**
     * Validate the given IPv6 address.
     *
     * @param address the IP address as a String.
     *
     * @return true if a valid IPv4 address, false otherwise
     */
    public static boolean isValidIPv6(
        String address)
    {
        if (address.length() == 0)
        {
            return false;
        }

        int octet;
        int octets = 0;

        String temp = address + ":";
        boolean doubleColonFound = false;
        int pos;
        int start = 0;
        while (start < temp.length()
            && (pos = temp.indexOf(':', start)) >= start)
        {
            if (octets == 8)
            {
                return false;
            }

            if (start != pos)
            {
                String value = temp.substring(start, pos);

                if (pos == (temp.length() - 1) && value.indexOf('.') > 0)
                {
                    if (!isValidIPv4(value))
                    {
                        return false;
                    }

                    octets++; // add an extra one as address covers 2 words.
                }
                else
                {
                    try
                    {
                        octet = Integer.parseInt(temp.substring(start, pos), 16);
                    }
                    catch (NumberFormatException ex)
                    {
                        return false;
                    }
                    if (octet < 0 || octet > 0xffff)
                    {
                        return false;
                    }
                }
            }
            else
            {
                if (pos != 1 && pos != temp.length() - 1 && doubleColonFound)
                {
                    return false;
                }
                doubleColonFound = true;
            }
            start = pos + 1;
            octets++;
        }

        return octets == 8 || doubleColonFound;
    }
}


