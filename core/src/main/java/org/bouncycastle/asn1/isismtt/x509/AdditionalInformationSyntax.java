package org.bouncycastle.asn1.isismtt.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.DirectoryString;

/**
 * Some other information of non-restrictive nature regarding the usage of this
 * certificate.
 * 
 * <pre>
 *    AdditionalInformationSyntax ::= DirectoryString (SIZE(1..2048))
 * </pre>
 */
public class AdditionalInformationSyntax
    extends ASN1Object
{
    private DirectoryString information;

    public static AdditionalInformationSyntax getInstance(Object obj)
    {
        if (obj instanceof AdditionalInformationSyntax)
        {
            return (AdditionalInformationSyntax)obj;
        }

        if (obj != null)
        {
            return new AdditionalInformationSyntax(DirectoryString.getInstance(obj));
        }

        return null;
    }

    private AdditionalInformationSyntax(DirectoryString information)
    {
        this.information = information;
    }

    /**
     * Constructor from a given details.
     *
     * @param information The describtion of the information.
     */
    public AdditionalInformationSyntax(String information)
    {
        this(new DirectoryString(information));
    }

    public DirectoryString getInformation()
    {
        return information;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p>
     * Returns:
     * <pre>
     *   AdditionalInformationSyntax ::= DirectoryString (SIZE(1..2048))
     * </pre>
     *
     * @return a DERObject
     */
    public ASN1Primitive toASN1Primitive()
    {
        return information.toASN1Primitive();
    }
}
