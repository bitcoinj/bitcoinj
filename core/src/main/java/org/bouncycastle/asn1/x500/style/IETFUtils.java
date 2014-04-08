package org.bouncycastle.asn1.x500.style;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class IETFUtils
{
    private static String unescape(String elt)
    {
        if (elt.length() == 0 || (elt.indexOf('\\') < 0 && elt.indexOf('"') < 0))
        {
            return elt.trim();
        }

        char[] elts = elt.toCharArray();
        boolean escaped = false;
        boolean quoted = false;
        StringBuffer buf = new StringBuffer(elt.length());
        int start = 0;

        // if it's an escaped hash string and not an actual encoding in string form
        // we need to leave it escaped.
        if (elts[0] == '\\')
        {
            if (elts[1] == '#')
            {
                start = 2;
                buf.append("\\#");
            }
        }

        boolean nonWhiteSpaceEncountered = false;
        int     lastEscaped = 0;
        char    hex1 = 0;

        for (int i = start; i != elts.length; i++)
        {
            char c = elts[i];

            if (c != ' ')
            {
                nonWhiteSpaceEncountered = true;
            }

            if (c == '"')
            {
                if (!escaped)
                {
                    quoted = !quoted;
                }
                else
                {
                    buf.append(c);
                }
                escaped = false;
            }
            else if (c == '\\' && !(escaped || quoted))
            {
                escaped = true;
                lastEscaped = buf.length();
            }
            else
            {
                if (c == ' ' && !escaped && !nonWhiteSpaceEncountered)
                {
                    continue;
                }
                if (escaped && isHexDigit(c))
                {
                    if (hex1 != 0)
                    {
                        buf.append((char)(convertHex(hex1) * 16 + convertHex(c)));
                        escaped = false;
                        hex1 = 0;
                        continue;
                    }
                    hex1 = c;
                    continue;
                }
                buf.append(c);
                escaped = false;
            }
        }

        if (buf.length() > 0)
        {
            while (buf.charAt(buf.length() - 1) == ' ' && lastEscaped != (buf.length() - 1))
            {
                buf.setLength(buf.length() - 1);
            }
        }

        return buf.toString();
    }

    private static boolean isHexDigit(char c)
    {
        return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
    }

    private static int convertHex(char c)
    {
        if ('0' <= c && c <= '9')
        {
            return c - '0';
        }
        if ('a' <= c && c <= 'f')
        {
            return c - 'a' + 10;
        }
        return c - 'A' + 10;
    }

    public static RDN[] rDNsFromString(String name, X500NameStyle x500Style)
    {
        X500NameTokenizer nTok = new X500NameTokenizer(name);
        X500NameBuilder builder = new X500NameBuilder(x500Style);

        while (nTok.hasMoreTokens())
        {
            String  token = nTok.nextToken();

            if (token.indexOf('+') > 0)
            {
                X500NameTokenizer   pTok = new X500NameTokenizer(token, '+');
                X500NameTokenizer   vTok = new X500NameTokenizer(pTok.nextToken(), '=');

                String              attr = vTok.nextToken();

                if (!vTok.hasMoreTokens())
                {
                    throw new IllegalArgumentException("badly formatted directory string");
                }

                String               value = vTok.nextToken();
                ASN1ObjectIdentifier oid = x500Style.attrNameToOID(attr.trim());

                if (pTok.hasMoreTokens())
                {
                    Vector oids = new Vector();
                    Vector values = new Vector();

                    oids.addElement(oid);
                    values.addElement(unescape(value));

                    while (pTok.hasMoreTokens())
                    {
                        vTok = new X500NameTokenizer(pTok.nextToken(), '=');

                        attr = vTok.nextToken();

                        if (!vTok.hasMoreTokens())
                        {
                            throw new IllegalArgumentException("badly formatted directory string");
                        }

                        value = vTok.nextToken();
                        oid = x500Style.attrNameToOID(attr.trim());


                        oids.addElement(oid);
                        values.addElement(unescape(value));
                    }

                    builder.addMultiValuedRDN(toOIDArray(oids), toValueArray(values));
                }
                else
                {
                    builder.addRDN(oid, unescape(value));
                }
            }
            else
            {
                X500NameTokenizer   vTok = new X500NameTokenizer(token, '=');

                String              attr = vTok.nextToken();

                if (!vTok.hasMoreTokens())
                {
                    throw new IllegalArgumentException("badly formatted directory string");
                }

                String               value = vTok.nextToken();
                ASN1ObjectIdentifier oid = x500Style.attrNameToOID(attr.trim());

                builder.addRDN(oid, unescape(value));
            }
        }

        return builder.build().getRDNs();
    }

    private static String[] toValueArray(Vector values)
    {
        String[] tmp = new String[values.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = (String)values.elementAt(i);
        }

        return tmp;
    }

    private static ASN1ObjectIdentifier[] toOIDArray(Vector oids)
    {
        ASN1ObjectIdentifier[] tmp = new ASN1ObjectIdentifier[oids.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = (ASN1ObjectIdentifier)oids.elementAt(i);
        }

        return tmp;
    }

    public static String[] findAttrNamesForOID(
        ASN1ObjectIdentifier oid,
        Hashtable            lookup)
    {
        int count = 0;
        for (Enumeration en = lookup.elements(); en.hasMoreElements();)
        {
            if (oid.equals(en.nextElement()))
            {
                count++;
            }
        }

        String[] aliases = new String[count];
        count = 0;

        for (Enumeration en = lookup.keys(); en.hasMoreElements();)
        {
            String key = (String)en.nextElement();
            if (oid.equals(lookup.get(key)))
            {
                aliases[count++] = key;
            }
        }

        return aliases;
    }

    public static ASN1ObjectIdentifier decodeAttrName(
        String      name,
        Hashtable   lookUp)
    {
        if (Strings.toUpperCase(name).startsWith("OID."))
        {
            return new ASN1ObjectIdentifier(name.substring(4));
        }
        else if (name.charAt(0) >= '0' && name.charAt(0) <= '9')
        {
            return new ASN1ObjectIdentifier(name);
        }

        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)lookUp.get(Strings.toLowerCase(name));
        if (oid == null)
        {
            throw new IllegalArgumentException("Unknown object id - " + name + " - passed to distinguished name");
        }

        return oid;
    }

    public static ASN1Encodable valueFromHexString(
        String  str,
        int     off)
        throws IOException
    {
        byte[] data = new byte[(str.length() - off) / 2];
        for (int index = 0; index != data.length; index++)
        {
            char left = str.charAt((index * 2) + off);
            char right = str.charAt((index * 2) + off + 1);

            data[index] = (byte)((convertHex(left) << 4) | convertHex(right));
        }

        return ASN1Primitive.fromByteArray(data);
    }

    public static void appendRDN(
        StringBuffer          buf,
        RDN                   rdn,
        Hashtable             oidSymbols)
    {
        if (rdn.isMultiValued())
        {
            AttributeTypeAndValue[] atv = rdn.getTypesAndValues();
            boolean firstAtv = true;

            for (int j = 0; j != atv.length; j++)
            {
                if (firstAtv)
                {
                    firstAtv = false;
                }
                else
                {
                    buf.append('+');
                }

                IETFUtils.appendTypeAndValue(buf, atv[j], oidSymbols);
            }
        }
        else
        {
            IETFUtils.appendTypeAndValue(buf, rdn.getFirst(), oidSymbols);
        }
    }

    public static void appendTypeAndValue(
        StringBuffer          buf,
        AttributeTypeAndValue typeAndValue,
        Hashtable             oidSymbols)
    {
        String  sym = (String)oidSymbols.get(typeAndValue.getType());

        if (sym != null)
        {
            buf.append(sym);
        }
        else
        {
            buf.append(typeAndValue.getType().getId());
        }

        buf.append('=');

        buf.append(valueToString(typeAndValue.getValue()));
    }

    public static String valueToString(ASN1Encodable value)
    {
        StringBuffer vBuf = new StringBuffer();

        if (value instanceof ASN1String && !(value instanceof DERUniversalString))
        {
            String v = ((ASN1String)value).getString();
            if (v.length() > 0 && v.charAt(0) == '#')
            {
                vBuf.append("\\" + v);
            }
            else
            {
                vBuf.append(v);
            }
        }
        else
        {
            try
            {
                vBuf.append("#" + bytesToString(Hex.encode(value.toASN1Primitive().getEncoded(ASN1Encoding.DER))));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("Other value has no encoded form");
            }
        }

        int     end = vBuf.length();
        int     index = 0;

        if (vBuf.length() >= 2 && vBuf.charAt(0) == '\\' && vBuf.charAt(1) == '#')
        {
            index += 2;
        }

        while (index != end)
        {
            if ((vBuf.charAt(index) == ',')
               || (vBuf.charAt(index) == '"')
               || (vBuf.charAt(index) == '\\')
               || (vBuf.charAt(index) == '+')
               || (vBuf.charAt(index) == '=')
               || (vBuf.charAt(index) == '<')
               || (vBuf.charAt(index) == '>')
               || (vBuf.charAt(index) == ';'))
            {
                vBuf.insert(index, "\\");
                index++;
                end++;
            }

            index++;
        }

        int start = 0;
        if (vBuf.length() > 0)
        {
            while (vBuf.length() > start && vBuf.charAt(start) == ' ')
            {
                vBuf.insert(start, "\\");
                start += 2;
            }
        }

        int endBuf = vBuf.length() - 1;

        while (endBuf >= 0 && vBuf.charAt(endBuf) == ' ')
        {
            vBuf.insert(endBuf, '\\');
            endBuf--;
        }

        return vBuf.toString();
    }

    private static String bytesToString(
        byte[] data)
    {
        char[]  cs = new char[data.length];

        for (int i = 0; i != cs.length; i++)
        {
            cs[i] = (char)(data[i] & 0xff);
        }

        return new String(cs);
    }

    public static String canonicalize(String s)
    {
        String value = Strings.toLowerCase(s.trim());

        if (value.length() > 0 && value.charAt(0) == '#')
        {
            ASN1Primitive obj = decodeObject(value);

            if (obj instanceof ASN1String)
            {
                value = Strings.toLowerCase(((ASN1String)obj).getString().trim());
            }
        }

        value = stripInternalSpaces(value);

        return value;
    }

    private static ASN1Primitive decodeObject(String oValue)
    {
        try
        {
            return ASN1Primitive.fromByteArray(Hex.decode(oValue.substring(1)));
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unknown encoding in name: " + e);
        }
    }

    public static String stripInternalSpaces(
        String str)
    {
        StringBuffer res = new StringBuffer();

        if (str.length() != 0)
        {
            char c1 = str.charAt(0);

            res.append(c1);

            for (int k = 1; k < str.length(); k++)
            {
                char c2 = str.charAt(k);
                if (!(c1 == ' ' && c2 == ' '))
                {
                    res.append(c2);
                }
                c1 = c2;
            }
        }

        return res.toString();
    }

    public static boolean rDNAreEqual(RDN rdn1, RDN rdn2)
    {
        if (rdn1.isMultiValued())
        {
            if (rdn2.isMultiValued())
            {
                AttributeTypeAndValue[] atvs1 = rdn1.getTypesAndValues();
                AttributeTypeAndValue[] atvs2 = rdn2.getTypesAndValues();

                if (atvs1.length != atvs2.length)
                {
                    return false;
                }

                for (int i = 0; i != atvs1.length; i++)
                {
                    if (!atvAreEqual(atvs1[i], atvs2[i]))
                    {
                        return false;
                    }
                }
            }
            else
            {
                return false;
            }
        }
        else
        {
            if (!rdn2.isMultiValued())
            {
                return atvAreEqual(rdn1.getFirst(), rdn2.getFirst());
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    private static boolean atvAreEqual(AttributeTypeAndValue atv1, AttributeTypeAndValue atv2)
    {
        if (atv1 == atv2)
        {
            return true;
        }

        if (atv1 == null)
        {
            return false;
        }

        if (atv2 == null)
        {
            return false;
        }

        ASN1ObjectIdentifier o1 = atv1.getType();
        ASN1ObjectIdentifier o2 = atv2.getType();

        if (!o1.equals(o2))
        {
            return false;
        }

        String v1 = IETFUtils.canonicalize(IETFUtils.valueToString(atv1.getValue()));
        String v2 = IETFUtils.canonicalize(IETFUtils.valueToString(atv2.getValue()));

        if (!v1.equals(v2))
        {
            return false;
        }

        return true;
    }
}
