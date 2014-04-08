package org.bouncycastle.asn1.x509;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * <pre>
 *     RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *     RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 *     AttributeTypeAndValue ::= SEQUENCE {
 *                                   type  OBJECT IDENTIFIER,
 *                                   value ANY }
 * </pre>
 * @deprecated use org.bouncycastle.asn1.x500.X500Name.
 */
public class X509Name
    extends ASN1Object
{
    /**
     * country code - StringType(SIZE(2))
     * @deprecated use a X500NameStyle
     */
    public static final ASN1ObjectIdentifier C = new ASN1ObjectIdentifier("2.5.4.6");

    /**
     * organization - StringType(SIZE(1..64))
     * @deprecated use a X500NameStyle
     */
    public static final ASN1ObjectIdentifier O = new ASN1ObjectIdentifier("2.5.4.10");

    /**
     * organizational unit name - StringType(SIZE(1..64))
     * @deprecated use a X500NameStyle
     */
    public static final ASN1ObjectIdentifier OU = new ASN1ObjectIdentifier("2.5.4.11");

    /**
     * Title
     * @deprecated use a X500NameStyle
     */
    public static final ASN1ObjectIdentifier T = new ASN1ObjectIdentifier("2.5.4.12");

    /**
     * common name - StringType(SIZE(1..64))
     * @deprecated use a X500NameStyle
     */
    public static final ASN1ObjectIdentifier CN = new ASN1ObjectIdentifier("2.5.4.3");

    /**
     * device serial number name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier SN = new ASN1ObjectIdentifier("2.5.4.5");

    /**
     * street - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier STREET = new ASN1ObjectIdentifier("2.5.4.9");
    
    /**
     * device serial number name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier SERIALNUMBER = SN;

    /**
     * locality name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier L = new ASN1ObjectIdentifier("2.5.4.7");

    /**
     * state, or province name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier ST = new ASN1ObjectIdentifier("2.5.4.8");

    /**
     * Naming attributes of type X520name
     */
    public static final ASN1ObjectIdentifier SURNAME = new ASN1ObjectIdentifier("2.5.4.4");
    public static final ASN1ObjectIdentifier GIVENNAME = new ASN1ObjectIdentifier("2.5.4.42");
    public static final ASN1ObjectIdentifier INITIALS = new ASN1ObjectIdentifier("2.5.4.43");
    public static final ASN1ObjectIdentifier GENERATION = new ASN1ObjectIdentifier("2.5.4.44");
    public static final ASN1ObjectIdentifier UNIQUE_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.45");

    /**
     * businessCategory - DirectoryString(SIZE(1..128)
     */
    public static final ASN1ObjectIdentifier BUSINESS_CATEGORY = new ASN1ObjectIdentifier(
                    "2.5.4.15");

    /**
     * postalCode - DirectoryString(SIZE(1..40)
     */
    public static final ASN1ObjectIdentifier POSTAL_CODE = new ASN1ObjectIdentifier(
                    "2.5.4.17");
    
    /**
     * dnQualifier - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier DN_QUALIFIER = new ASN1ObjectIdentifier(
                    "2.5.4.46");

    /**
     * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier PSEUDONYM = new ASN1ObjectIdentifier(
                    "2.5.4.65");


    /**
     * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z
     */
    public static final ASN1ObjectIdentifier DATE_OF_BIRTH = new ASN1ObjectIdentifier(
                    "1.3.6.1.5.5.7.9.1");

    /**
     * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
     */
    public static final ASN1ObjectIdentifier PLACE_OF_BIRTH = new ASN1ObjectIdentifier(
                    "1.3.6.1.5.5.7.9.2");

    /**
     * RFC 3039 Gender - PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
     */
    public static final ASN1ObjectIdentifier GENDER = new ASN1ObjectIdentifier(
                    "1.3.6.1.5.5.7.9.3");

    /**
     * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
     * codes only
     */
    public static final ASN1ObjectIdentifier COUNTRY_OF_CITIZENSHIP = new ASN1ObjectIdentifier(
                    "1.3.6.1.5.5.7.9.4");

    /**
     * RFC 3039 CountryOfResidence - PrintableString (SIZE (2)) -- ISO 3166
     * codes only
     */
    public static final ASN1ObjectIdentifier COUNTRY_OF_RESIDENCE = new ASN1ObjectIdentifier(
                    "1.3.6.1.5.5.7.9.5");


    /**
     * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier NAME_AT_BIRTH =  new ASN1ObjectIdentifier("1.3.36.8.3.14");

    /**
     * RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
     * DirectoryString(SIZE(1..30))
     */
    public static final ASN1ObjectIdentifier POSTAL_ADDRESS = new ASN1ObjectIdentifier("2.5.4.16");

    /**
     * RFC 2256 dmdName
     */
    public static final ASN1ObjectIdentifier DMD_NAME = new ASN1ObjectIdentifier("2.5.4.54");

    /**
     * id-at-telephoneNumber
     */
    public static final ASN1ObjectIdentifier TELEPHONE_NUMBER = X509ObjectIdentifiers.id_at_telephoneNumber;

    /**
     * id-at-name
     */
    public static final ASN1ObjectIdentifier NAME = X509ObjectIdentifiers.id_at_name;

    /**
     * Email address (RSA PKCS#9 extension) - IA5String.
     * <p>Note: if you're trying to be ultra orthodox, don't use this! It shouldn't be in here.
     * @deprecated use a X500NameStyle
     */
    public static final ASN1ObjectIdentifier EmailAddress = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;
    
    /**
     * more from PKCS#9
     */
    public static final ASN1ObjectIdentifier UnstructuredName = PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;
    public static final ASN1ObjectIdentifier UnstructuredAddress = PKCSObjectIdentifiers.pkcs_9_at_unstructuredAddress;
    
    /**
     * email address in Verisign certificates
     */
    public static final ASN1ObjectIdentifier E = EmailAddress;
    
    /*
     * others...
     */
    public static final ASN1ObjectIdentifier DC = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25");

    /**
     * LDAP User id.
     */
    public static final ASN1ObjectIdentifier UID = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1");

    /**
     * determines whether or not strings should be processed and printed
     * from back to front.
     */
    public static boolean DefaultReverse = false;

    /**
     * default look up table translating OID values into their common symbols following
     * the convention in RFC 2253 with a few extras
     */
    public static final Hashtable DefaultSymbols = new Hashtable();

    /**
     * look up table translating OID values into their common symbols following the convention in RFC 2253
     * 
     */
    public static final Hashtable RFC2253Symbols = new Hashtable();

    /**
     * look up table translating OID values into their common symbols following the convention in RFC 1779
     * 
     */
    public static final Hashtable RFC1779Symbols = new Hashtable();

    /**
     * look up table translating common symbols into their OIDS.
     */
    public static final Hashtable DefaultLookUp = new Hashtable();

    /**
     * look up table translating OID values into their common symbols
     * @deprecated use DefaultSymbols
     */
    public static final Hashtable OIDLookUp = DefaultSymbols;

    /**
     * look up table translating string values into their OIDS -
     * @deprecated use DefaultLookUp
     */
    public static final Hashtable SymbolLookUp = DefaultLookUp;

    private static final Boolean TRUE = new Boolean(true); // for J2ME compatibility
    private static final Boolean FALSE = new Boolean(false);

    static
    {
        DefaultSymbols.put(C, "C");
        DefaultSymbols.put(O, "O");
        DefaultSymbols.put(T, "T");
        DefaultSymbols.put(OU, "OU");
        DefaultSymbols.put(CN, "CN");
        DefaultSymbols.put(L, "L");
        DefaultSymbols.put(ST, "ST");
        DefaultSymbols.put(SN, "SERIALNUMBER");
        DefaultSymbols.put(EmailAddress, "E");
        DefaultSymbols.put(DC, "DC");
        DefaultSymbols.put(UID, "UID");
        DefaultSymbols.put(STREET, "STREET");
        DefaultSymbols.put(SURNAME, "SURNAME");
        DefaultSymbols.put(GIVENNAME, "GIVENNAME");
        DefaultSymbols.put(INITIALS, "INITIALS");
        DefaultSymbols.put(GENERATION, "GENERATION");
        DefaultSymbols.put(UnstructuredAddress, "unstructuredAddress");
        DefaultSymbols.put(UnstructuredName, "unstructuredName");
        DefaultSymbols.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
        DefaultSymbols.put(DN_QUALIFIER, "DN");
        DefaultSymbols.put(PSEUDONYM, "Pseudonym");
        DefaultSymbols.put(POSTAL_ADDRESS, "PostalAddress");
        DefaultSymbols.put(NAME_AT_BIRTH, "NameAtBirth");
        DefaultSymbols.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
        DefaultSymbols.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
        DefaultSymbols.put(GENDER, "Gender");
        DefaultSymbols.put(PLACE_OF_BIRTH, "PlaceOfBirth");
        DefaultSymbols.put(DATE_OF_BIRTH, "DateOfBirth");
        DefaultSymbols.put(POSTAL_CODE, "PostalCode");
        DefaultSymbols.put(BUSINESS_CATEGORY, "BusinessCategory");
        DefaultSymbols.put(TELEPHONE_NUMBER, "TelephoneNumber");
        DefaultSymbols.put(NAME, "Name");

        RFC2253Symbols.put(C, "C");
        RFC2253Symbols.put(O, "O");
        RFC2253Symbols.put(OU, "OU");
        RFC2253Symbols.put(CN, "CN");
        RFC2253Symbols.put(L, "L");
        RFC2253Symbols.put(ST, "ST");
        RFC2253Symbols.put(STREET, "STREET");
        RFC2253Symbols.put(DC, "DC");
        RFC2253Symbols.put(UID, "UID");

        RFC1779Symbols.put(C, "C");
        RFC1779Symbols.put(O, "O");
        RFC1779Symbols.put(OU, "OU");
        RFC1779Symbols.put(CN, "CN");
        RFC1779Symbols.put(L, "L");
        RFC1779Symbols.put(ST, "ST");
        RFC1779Symbols.put(STREET, "STREET");

        DefaultLookUp.put("c", C);
        DefaultLookUp.put("o", O);
        DefaultLookUp.put("t", T);
        DefaultLookUp.put("ou", OU);
        DefaultLookUp.put("cn", CN);
        DefaultLookUp.put("l", L);
        DefaultLookUp.put("st", ST);
        DefaultLookUp.put("sn", SN);
        DefaultLookUp.put("serialnumber", SN);
        DefaultLookUp.put("street", STREET);
        DefaultLookUp.put("emailaddress", E);
        DefaultLookUp.put("dc", DC);
        DefaultLookUp.put("e", E);
        DefaultLookUp.put("uid", UID);
        DefaultLookUp.put("surname", SURNAME);
        DefaultLookUp.put("givenname", GIVENNAME);
        DefaultLookUp.put("initials", INITIALS);
        DefaultLookUp.put("generation", GENERATION);
        DefaultLookUp.put("unstructuredaddress", UnstructuredAddress);
        DefaultLookUp.put("unstructuredname", UnstructuredName);
        DefaultLookUp.put("uniqueidentifier", UNIQUE_IDENTIFIER);
        DefaultLookUp.put("dn", DN_QUALIFIER);
        DefaultLookUp.put("pseudonym", PSEUDONYM);
        DefaultLookUp.put("postaladdress", POSTAL_ADDRESS);
        DefaultLookUp.put("nameofbirth", NAME_AT_BIRTH);
        DefaultLookUp.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
        DefaultLookUp.put("countryofresidence", COUNTRY_OF_RESIDENCE);
        DefaultLookUp.put("gender", GENDER);
        DefaultLookUp.put("placeofbirth", PLACE_OF_BIRTH);
        DefaultLookUp.put("dateofbirth", DATE_OF_BIRTH);
        DefaultLookUp.put("postalcode", POSTAL_CODE);
        DefaultLookUp.put("businesscategory", BUSINESS_CATEGORY);
        DefaultLookUp.put("telephonenumber", TELEPHONE_NUMBER);
        DefaultLookUp.put("name", NAME);
    }

    private X509NameEntryConverter  converter = null;
    private Vector                  ordering = new Vector();
    private Vector                  values = new Vector();
    private Vector                  added = new Vector();

    private ASN1Sequence            seq;

    private boolean                 isHashCodeCalculated;
    private int                     hashCodeValue;

    /**
     * Return a X509Name based on the passed in tagged object.
     * 
     * @param obj tag object holding name.
     * @param explicit true if explicitly tagged false otherwise.
     * @return the X509Name
     */
    public static X509Name getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static X509Name getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof X509Name)
        {
            return (X509Name)obj;
        }
        else if (obj instanceof X500Name)
        {
            return new X509Name(ASN1Sequence.getInstance(((X500Name)obj).toASN1Primitive()));
        }
        else if (obj != null)
        {
            return new X509Name(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected X509Name()
    {
        // constructure use by new X500 Name class
    }
    /**
     * Constructor from ASN1Sequence
     *
     * the principal will be a list of constructed sets, each containing an (OID, String) pair.
     * @deprecated use X500Name.getInstance()
     */
    public X509Name(
        ASN1Sequence  seq)
    {
        this.seq = seq;

        Enumeration e = seq.getObjects();

        while (e.hasMoreElements())
        {
            ASN1Set         set = ASN1Set.getInstance(((ASN1Encodable)e.nextElement()).toASN1Primitive());

            for (int i = 0; i < set.size(); i++) 
            {
                   ASN1Sequence s = ASN1Sequence.getInstance(set.getObjectAt(i).toASN1Primitive());

                   if (s.size() != 2)
                   {
                       throw new IllegalArgumentException("badly sized pair");
                   }

                   ordering.addElement(ASN1ObjectIdentifier.getInstance(s.getObjectAt(0)));
                   
                   ASN1Encodable value = s.getObjectAt(1);
                   if (value instanceof ASN1String && !(value instanceof DERUniversalString))
                   {
                       String v = ((ASN1String)value).getString();
                       if (v.length() > 0 && v.charAt(0) == '#')
                       {
                           values.addElement("\\" + v);
                       }
                       else
                       {
                           values.addElement(v);
                       }
                   }
                   else
                   {
                       try
                       {
                           values.addElement("#" + bytesToString(Hex.encode(value.toASN1Primitive().getEncoded(ASN1Encoding.DER))));
                       }
                       catch (IOException e1)
                       {
                           throw new IllegalArgumentException("cannot encode value");
                       }
                   }
                   added.addElement((i != 0) ? TRUE : FALSE);  // to allow earlier JDK compatibility
            }
        }
    }

    /**
     * constructor from a table of attributes.
     * <p>
     * it's is assumed the table contains OID/String pairs, and the contents
     * of the table are copied into an internal table as part of the
     * construction process.
     * <p>
     * <b>Note:</b> if the name you are trying to generate should be
     * following a specific ordering, you should use the constructor
     * with the ordering specified below.
     * @deprecated use an ordered constructor! The hashtable ordering is rarely correct
     */
    public X509Name(
        Hashtable  attributes)
    {
        this(null, attributes);
    }

    /**
     * Constructor from a table of attributes with ordering.
     * <p>
     * it's is assumed the table contains OID/String pairs, and the contents
     * of the table are copied into an internal table as part of the
     * construction process. The ordering vector should contain the OIDs
     * in the order they are meant to be encoded or printed in toString.
     */
    public X509Name(
        Vector      ordering,
        Hashtable   attributes)
    {
        this(ordering, attributes, new X509DefaultEntryConverter());
    }

    /**
     * Constructor from a table of attributes with ordering.
     * <p>
     * it's is assumed the table contains OID/String pairs, and the contents
     * of the table are copied into an internal table as part of the
     * construction process. The ordering vector should contain the OIDs
     * in the order they are meant to be encoded or printed in toString.
     * <p>
     * The passed in converter will be used to convert the strings into their
     * ASN.1 counterparts.
     * @deprecated use X500Name, X500NameBuilder
     */
    public X509Name(
        Vector                   ordering,
        Hashtable                attributes,
        X509NameEntryConverter   converter)
    {
        this.converter = converter;

        if (ordering != null)
        {
            for (int i = 0; i != ordering.size(); i++)
            {
                this.ordering.addElement(ordering.elementAt(i));
                this.added.addElement(FALSE);
            }
        }
        else
        {
            Enumeration     e = attributes.keys();

            while (e.hasMoreElements())
            {
                this.ordering.addElement(e.nextElement());
                this.added.addElement(FALSE);
            }
        }

        for (int i = 0; i != this.ordering.size(); i++)
        {
            ASN1ObjectIdentifier     oid = (ASN1ObjectIdentifier)this.ordering.elementAt(i);

            if (attributes.get(oid) == null)
            {
                throw new IllegalArgumentException("No attribute for object id - " + oid.getId() + " - passed to distinguished name");
            }

            this.values.addElement(attributes.get(oid)); // copy the hash table
        }
    }

    /**
     * Takes two vectors one of the oids and the other of the values.
     * @deprecated use X500Name, X500NameBuilder
     */
    public X509Name(
        Vector  oids,
        Vector  values)
    {
        this(oids, values, new X509DefaultEntryConverter());
    }

    /**
     * Takes two vectors one of the oids and the other of the values.
     * <p>
     * The passed in converter will be used to convert the strings into their
     * ASN.1 counterparts.
     * @deprecated use X500Name, X500NameBuilder
     */
    public X509Name(
        Vector                  oids,
        Vector                  values,
        X509NameEntryConverter  converter)
    {
        this.converter = converter;

        if (oids.size() != values.size())
        {
            throw new IllegalArgumentException("oids vector must be same length as values.");
        }

        for (int i = 0; i < oids.size(); i++)
        {
            this.ordering.addElement(oids.elementAt(i));
            this.values.addElement(values.elementAt(i));
            this.added.addElement(FALSE);
        }
    }

//    private Boolean isEncoded(String s)
//    {
//        if (s.charAt(0) == '#')
//        {
//            return TRUE;
//        }
//
//        return FALSE;
//    }

    /**
     * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
     * some such, converting it into an ordered set of name attributes.
     * @deprecated use X500Name, X500NameBuilder
     */
    public X509Name(
        String  dirName)
    {
        this(DefaultReverse, DefaultLookUp, dirName);
    }

    /**
     * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
     * some such, converting it into an ordered set of name attributes with each
     * string value being converted to its associated ASN.1 type using the passed
     * in converter.
     * @deprecated use X500Name, X500NameBuilder
     */
    public X509Name(
        String                  dirName,
        X509NameEntryConverter  converter)
    {
        this(DefaultReverse, DefaultLookUp, dirName, converter);
    }

    /**
     * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
     * some such, converting it into an ordered set of name attributes. If reverse
     * is true, create the encoded version of the sequence starting from the
     * last element in the string.
     * @deprecated use X500Name, X500NameBuilder
     */
    public X509Name(
        boolean reverse,
        String  dirName)
    {
        this(reverse, DefaultLookUp, dirName);
    }

    /**
     * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
     * some such, converting it into an ordered set of name attributes with each
     * string value being converted to its associated ASN.1 type using the passed
     * in converter. If reverse is true the ASN.1 sequence representing the DN will
     * be built by starting at the end of the string, rather than the start.
     * @deprecated use X500Name, X500NameBuilder
     */
    public X509Name(
        boolean                 reverse,
        String                  dirName,
        X509NameEntryConverter  converter)
    {
        this(reverse, DefaultLookUp, dirName, converter);
    }

    /**
     * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
     * some such, converting it into an ordered set of name attributes. lookUp
     * should provide a table of lookups, indexed by lowercase only strings and
     * yielding a ASN1ObjectIdentifier, other than that OID. and numeric oids
     * will be processed automatically.
     * <br>
     * If reverse is true, create the encoded version of the sequence
     * starting from the last element in the string.
     * @param reverse true if we should start scanning from the end (RFC 2553).
     * @param lookUp table of names and their oids.
     * @param dirName the X.500 string to be parsed.
     * @deprecated use X500Name, X500NameBuilder
     */
    public X509Name(
        boolean     reverse,
        Hashtable   lookUp,
        String      dirName)
    {
        this(reverse, lookUp, dirName, new X509DefaultEntryConverter());
    }

    private ASN1ObjectIdentifier decodeOID(
        String      name,
        Hashtable   lookUp)
    {
        name = name.trim();
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

    private String unescape(String elt)
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

    /**
     * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
     * some such, converting it into an ordered set of name attributes. lookUp
     * should provide a table of lookups, indexed by lowercase only strings and
     * yielding a ASN1ObjectIdentifier, other than that OID. and numeric oids
     * will be processed automatically. The passed in converter is used to convert the
     * string values to the right of each equals sign to their ASN.1 counterparts.
     * <br>
     * @param reverse true if we should start scanning from the end, false otherwise.
     * @param lookUp table of names and oids.
     * @param dirName the string dirName
     * @param converter the converter to convert string values into their ASN.1 equivalents
     */
    public X509Name(
        boolean                 reverse,
        Hashtable               lookUp,
        String                  dirName,
        X509NameEntryConverter  converter)
    {
        this.converter = converter;
        X509NameTokenizer   nTok = new X509NameTokenizer(dirName);

        while (nTok.hasMoreTokens())
        {
            String  token = nTok.nextToken();

            if (token.indexOf('+') > 0)
            {
                X509NameTokenizer   pTok = new X509NameTokenizer(token, '+');

                addEntry(lookUp, pTok.nextToken(), FALSE);

                while (pTok.hasMoreTokens())
                {
                    addEntry(lookUp, pTok.nextToken(), TRUE);
                }
            }
            else
            {
                addEntry(lookUp, token, FALSE);
            }
        }

        if (reverse)
        {
            Vector  o = new Vector();
            Vector  v = new Vector();
            Vector  a = new Vector();

            int count = 1;

            for (int i = 0; i < this.ordering.size(); i++)
            {
                if (((Boolean)this.added.elementAt(i)).booleanValue())
                {
                    o.insertElementAt(this.ordering.elementAt(i), count);
                    v.insertElementAt(this.values.elementAt(i), count);
                    a.insertElementAt(this.added.elementAt(i), count);
                    count++;
                }
                else
                {
                    o.insertElementAt(this.ordering.elementAt(i), 0);
                    v.insertElementAt(this.values.elementAt(i), 0);
                    a.insertElementAt(this.added.elementAt(i), 0);
                    count = 1;
                }
            }

            this.ordering = o;
            this.values = v;
            this.added = a;
        }
    }

    private void addEntry(Hashtable lookUp, String token, Boolean isAdded)
    {
        X509NameTokenizer vTok;
        String name;
        String value;ASN1ObjectIdentifier oid;
        vTok = new X509NameTokenizer(token, '=');

        name = vTok.nextToken();

        if (!vTok.hasMoreTokens())
        {
           throw new IllegalArgumentException("badly formatted directory string");
        }

        value = vTok.nextToken();

        oid = decodeOID(name, lookUp);

        this.ordering.addElement(oid);
        this.values.addElement(unescape(value));
        this.added.addElement(isAdded);
    }

    /**
     * return a vector of the oids in the name, in the order they were found.
     */
    public Vector getOIDs()
    {
        Vector  v = new Vector();

        for (int i = 0; i != ordering.size(); i++)
        {
            v.addElement(ordering.elementAt(i));
        }

        return v;
    }

    /**
     * return a vector of the values found in the name, in the order they
     * were found.
     */
    public Vector getValues()
    {
        Vector  v = new Vector();

        for (int i = 0; i != values.size(); i++)
        {
            v.addElement(values.elementAt(i));
        }

        return v;
    }

    /**
     * return a vector of the values found in the name, in the order they
     * were found, with the DN label corresponding to passed in oid.
     */
    public Vector getValues(
        ASN1ObjectIdentifier oid)
    {
        Vector  v = new Vector();

        for (int i = 0; i != values.size(); i++)
        {
            if (ordering.elementAt(i).equals(oid))
            {
                String val = (String)values.elementAt(i);

                if (val.length() > 2 && val.charAt(0) == '\\' && val.charAt(1) == '#')
                {
                    v.addElement(val.substring(1));
                }
                else
                {
                    v.addElement(val);
                }
            }
        }

        return v;
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (seq == null)
        {
            ASN1EncodableVector  vec = new ASN1EncodableVector();
            ASN1EncodableVector  sVec = new ASN1EncodableVector();
            ASN1ObjectIdentifier  lstOid = null;
            
            for (int i = 0; i != ordering.size(); i++)
            {
                ASN1EncodableVector     v = new ASN1EncodableVector();
                ASN1ObjectIdentifier     oid = (ASN1ObjectIdentifier)ordering.elementAt(i);

                v.add(oid);

                String  str = (String)values.elementAt(i);

                v.add(converter.getConvertedValue(oid, str));
 
                if (lstOid == null 
                    || ((Boolean)this.added.elementAt(i)).booleanValue())
                {
                    sVec.add(new DERSequence(v));
                }
                else
                {
                    vec.add(new DERSet(sVec));
                    sVec = new ASN1EncodableVector();
                    
                    sVec.add(new DERSequence(v));
                }
                
                lstOid = oid;
            }
            
            vec.add(new DERSet(sVec));
            
            seq = new DERSequence(vec);
        }

        return seq;
    }

    /**
     * @param inOrder if true the order of both X509 names must be the same,
     * as well as the values associated with each element.
     */
    public boolean equals(Object obj, boolean inOrder)
    {
        if (!inOrder)
        {
            return this.equals(obj);
        }

        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof X509Name || obj instanceof ASN1Sequence))
        {
            return false;
        }

        ASN1Primitive derO = ((ASN1Encodable)obj).toASN1Primitive();

        if (this.toASN1Primitive().equals(derO))
        {
            return true;
        }

        X509Name other;

        try
        {
            other = X509Name.getInstance(obj);
        }
        catch (IllegalArgumentException e)
        {
            return false;
        }

        int      orderingSize = ordering.size();

        if (orderingSize != other.ordering.size())
        {
            return false;
        }

        for (int i = 0; i < orderingSize; i++)
        {
            ASN1ObjectIdentifier  oid = (ASN1ObjectIdentifier)ordering.elementAt(i);
            ASN1ObjectIdentifier  oOid = (ASN1ObjectIdentifier)other.ordering.elementAt(i);

            if (oid.equals(oOid))
            {
                String value = (String)values.elementAt(i);
                String oValue = (String)other.values.elementAt(i);

                if (!equivalentStrings(value, oValue))
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    public int hashCode()
    {
        if (isHashCodeCalculated)
        {
            return hashCodeValue;
        }

        isHashCodeCalculated = true;

        // this needs to be order independent, like equals
        for (int i = 0; i != ordering.size(); i += 1)
        {
            String value = (String)values.elementAt(i);

            value = canonicalize(value);
            value = stripInternalSpaces(value);

            hashCodeValue ^= ordering.elementAt(i).hashCode();
            hashCodeValue ^= value.hashCode();
        }

        return hashCodeValue;
    }

    /**
     * test for equality - note: case is ignored.
     */
    public boolean equals(Object obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof X509Name || obj instanceof ASN1Sequence))
        {
            return false;
        }
        
        ASN1Primitive derO = ((ASN1Encodable)obj).toASN1Primitive();
        
        if (this.toASN1Primitive().equals(derO))
        {
            return true;
        }

        X509Name other;

        try
        {
            other = X509Name.getInstance(obj);
        }
        catch (IllegalArgumentException e)
        { 
            return false;
        }

        int      orderingSize = ordering.size();

        if (orderingSize != other.ordering.size())
        {
            return false;
        }
        
        boolean[] indexes = new boolean[orderingSize];
        int       start, end, delta;

        if (ordering.elementAt(0).equals(other.ordering.elementAt(0)))   // guess forward
        {
            start = 0;
            end = orderingSize;
            delta = 1;
        }
        else  // guess reversed - most common problem
        {
            start = orderingSize - 1;
            end = -1;
            delta = -1;
        }

        for (int i = start; i != end; i += delta)
        {
            boolean              found = false;
            ASN1ObjectIdentifier  oid = (ASN1ObjectIdentifier)ordering.elementAt(i);
            String               value = (String)values.elementAt(i);

            for (int j = 0; j < orderingSize; j++)
            {
                if (indexes[j])
                {
                    continue;
                }

                ASN1ObjectIdentifier oOid = (ASN1ObjectIdentifier)other.ordering.elementAt(j);

                if (oid.equals(oOid))
                {
                    String oValue = (String)other.values.elementAt(j);

                    if (equivalentStrings(value, oValue))
                    {
                        indexes[j] = true;
                        found      = true;
                        break;
                    }
                }
            }

            if (!found)
            {
                return false;
            }
        }
        
        return true;
    }

    private boolean equivalentStrings(String s1, String s2)
    {
        String value = canonicalize(s1);
        String oValue = canonicalize(s2);
        
        if (!value.equals(oValue))
        {
            value = stripInternalSpaces(value);
            oValue = stripInternalSpaces(oValue);

            if (!value.equals(oValue))
            {
                return false;
            }
        }

        return true;
    }

    private String canonicalize(String s)
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

        return value;
    }

    private ASN1Primitive decodeObject(String oValue)
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

    private String stripInternalSpaces(
        String str)
    {
        StringBuffer res = new StringBuffer();

        if (str.length() != 0)
        {
            char    c1 = str.charAt(0);

            res.append(c1);

            for (int k = 1; k < str.length(); k++)
            {
                char    c2 = str.charAt(k);
                if (!(c1 == ' ' && c2 == ' '))
                {
                    res.append(c2);
                }
                c1 = c2;
            }
        }

        return res.toString();
    }

    private void appendValue(
        StringBuffer        buf,
        Hashtable           oidSymbols,
        ASN1ObjectIdentifier oid,
        String              value)
    {
        String  sym = (String)oidSymbols.get(oid);

        if (sym != null)
        {
            buf.append(sym);
        }
        else
        {
            buf.append(oid.getId());
        }

        buf.append('=');

        int start = buf.length();
        buf.append(value);
        int end = buf.length();

        if (value.length() >= 2 && value.charAt(0) == '\\' && value.charAt(1) == '#')
        {
            start += 2;
        }

        while (start < end && buf.charAt(start) == ' ')
        {
            buf.insert(start, "\\");
            start += 2;
            ++end;
        }

        while (--end > start && buf.charAt(end) == ' ')
        {
            buf.insert(end, '\\');
        }

        while (start <= end)
        {
            switch (buf.charAt(start))
            {
            case ',':
            case '"':
            case '\\':
            case '+':
            case '=':
            case '<':
            case '>':
            case ';':
                buf.insert(start, "\\");
                start += 2;
                ++end;
                break;
            default:
                ++start;
                break;
            }
        }
    }

    /**
     * convert the structure to a string - if reverse is true the
     * oids and values are listed out starting with the last element
     * in the sequence (ala RFC 2253), otherwise the string will begin
     * with the first element of the structure. If no string definition
     * for the oid is found in oidSymbols the string value of the oid is
     * added. Two standard symbol tables are provided DefaultSymbols, and
     * RFC2253Symbols as part of this class.
     *
     * @param reverse if true start at the end of the sequence and work back.
     * @param oidSymbols look up table strings for oids.
     */
    public String toString(
        boolean     reverse,
        Hashtable   oidSymbols)
    {
        StringBuffer            buf = new StringBuffer();
        Vector                  components = new Vector();
        boolean                 first = true;

        StringBuffer ava = null;

        for (int i = 0; i < ordering.size(); i++)
        {
            if (((Boolean)added.elementAt(i)).booleanValue())
            {
                ava.append('+');
                appendValue(ava, oidSymbols,
                    (ASN1ObjectIdentifier)ordering.elementAt(i),
                    (String)values.elementAt(i));
            }
            else
            {
                ava = new StringBuffer();
                appendValue(ava, oidSymbols,
                    (ASN1ObjectIdentifier)ordering.elementAt(i),
                    (String)values.elementAt(i));
                components.addElement(ava);
            }
        }

        if (reverse)
        {
            for (int i = components.size() - 1; i >= 0; i--)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    buf.append(',');
                }

                buf.append(components.elementAt(i).toString());
            }
        }
        else
        {
            for (int i = 0; i < components.size(); i++)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    buf.append(',');
                }

                buf.append(components.elementAt(i).toString());
            }
        }

        return buf.toString();
    }

    private String bytesToString(
        byte[] data)
    {
        char[]  cs = new char[data.length];

        for (int i = 0; i != cs.length; i++)
        {
            cs[i] = (char)(data[i] & 0xff);
        }

        return new String(cs);
    }
    
    public String toString()
    {
        return toString(DefaultReverse, DefaultSymbols);
    }
}
