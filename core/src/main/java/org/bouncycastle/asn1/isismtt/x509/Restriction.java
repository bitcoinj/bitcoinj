package org.bouncycastle.asn1.isismtt.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.DirectoryString;

/**
 * Some other restriction regarding the usage of this certificate.
 *
 * <pre>
 *  RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
 * </pre>
 */
public class Restriction
    extends ASN1Object
{
    private DirectoryString restriction;

    public static Restriction getInstance(Object obj)
    {
        if (obj instanceof Restriction)
        {
            return (Restriction)obj;
        }

        if (obj != null)
        {
            return new Restriction(DirectoryString.getInstance(obj));
        }

        return null;
    }

    /**
     * Constructor from DirectoryString.
     * <p/>
     * The DirectoryString is of type RestrictionSyntax:
     * <p/>
     * <pre>
     *      RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
     * </pre>
     *
     * @param restriction A DirectoryString.
     */
    private Restriction(DirectoryString restriction)
    {
        this.restriction = restriction;
    }

    /**
     * Constructor from a given details.
     *
     * @param restriction The describtion of the restriction.
     */
    public Restriction(String restriction)
    {
        this.restriction = new DirectoryString(restriction);
    }

    public DirectoryString getRestriction()
    {
        return restriction;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p>
     * Returns:
     * <pre>
     *      RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
     * </pre>
     *
     * @return a DERObject
     */
    public ASN1Primitive toASN1Primitive()
    {
        return restriction.toASN1Primitive();
    }
}
