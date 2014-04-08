package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 * IssuingDistributionPoint ::= SEQUENCE { 
 *   distributionPoint          [0] DistributionPointName OPTIONAL, 
 *   onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE, 
 *   onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE, 
 *   onlySomeReasons            [3] ReasonFlags OPTIONAL, 
 *   indirectCRL                [4] BOOLEAN DEFAULT FALSE,
 *   onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
 * </pre>
 */
public class IssuingDistributionPoint
    extends ASN1Object
{
    private DistributionPointName distributionPoint;

    private boolean onlyContainsUserCerts;

    private boolean onlyContainsCACerts;

    private ReasonFlags onlySomeReasons;

    private boolean indirectCRL;

    private boolean onlyContainsAttributeCerts;

    private ASN1Sequence seq;

    public static IssuingDistributionPoint getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static IssuingDistributionPoint getInstance(
        Object obj)
    {
        if (obj instanceof IssuingDistributionPoint)
        {
            return (IssuingDistributionPoint)obj;
        }
        else if (obj != null)
        {
            return new IssuingDistributionPoint(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Constructor from given details.
     * 
     * @param distributionPoint
     *            May contain an URI as pointer to most current CRL.
     * @param onlyContainsUserCerts Covers revocation information for end certificates.
     * @param onlyContainsCACerts Covers revocation information for CA certificates.
     * 
     * @param onlySomeReasons
     *            Which revocation reasons does this point cover.
     * @param indirectCRL
     *            If <code>true</code> then the CRL contains revocation
     *            information about certificates ssued by other CAs.
     * @param onlyContainsAttributeCerts Covers revocation information for attribute certificates.
     */
    public IssuingDistributionPoint(
        DistributionPointName distributionPoint,
        boolean onlyContainsUserCerts,
        boolean onlyContainsCACerts,
        ReasonFlags onlySomeReasons,
        boolean indirectCRL,
        boolean onlyContainsAttributeCerts)
    {
        this.distributionPoint = distributionPoint;
        this.indirectCRL = indirectCRL;
        this.onlyContainsAttributeCerts = onlyContainsAttributeCerts;
        this.onlyContainsCACerts = onlyContainsCACerts;
        this.onlyContainsUserCerts = onlyContainsUserCerts;
        this.onlySomeReasons = onlySomeReasons;

        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (distributionPoint != null)
        {                                    // CHOICE item so explicitly tagged
            vec.add(new DERTaggedObject(true, 0, distributionPoint));
        }
        if (onlyContainsUserCerts)
        {
            vec.add(new DERTaggedObject(false, 1, ASN1Boolean.getInstance(true)));
        }
        if (onlyContainsCACerts)
        {
            vec.add(new DERTaggedObject(false, 2, ASN1Boolean.getInstance(true)));
        }
        if (onlySomeReasons != null)
        {
            vec.add(new DERTaggedObject(false, 3, onlySomeReasons));
        }
        if (indirectCRL)
        {
            vec.add(new DERTaggedObject(false, 4, ASN1Boolean.getInstance(true)));
        }
        if (onlyContainsAttributeCerts)
        {
            vec.add(new DERTaggedObject(false, 5, ASN1Boolean.getInstance(true)));
        }

        seq = new DERSequence(vec);
    }

    /**
     * Shorthand Constructor from given details.
     *
     * @param distributionPoint
     *            May contain an URI as pointer to most current CRL.
     * @param indirectCRL
     *            If <code>true</code> then the CRL contains revocation
     *            information about certificates ssued by other CAs.
     * @param onlyContainsAttributeCerts Covers revocation information for attribute certificates.
     */
    public IssuingDistributionPoint(
        DistributionPointName distributionPoint,
        boolean indirectCRL,
        boolean onlyContainsAttributeCerts)
    {
        this(distributionPoint, false, false, null, indirectCRL, onlyContainsAttributeCerts);
    }

    /**
     * Constructor from ASN1Sequence
     */
    private IssuingDistributionPoint(
        ASN1Sequence seq)
    {
        this.seq = seq;

        for (int i = 0; i != seq.size(); i++)
        {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(seq.getObjectAt(i));

            switch (o.getTagNo())
            {
            case 0:
                                                    // CHOICE so explicit
                distributionPoint = DistributionPointName.getInstance(o, true);
                break;
            case 1:
                onlyContainsUserCerts = ASN1Boolean.getInstance(o, false).isTrue();
                break;
            case 2:
                onlyContainsCACerts = ASN1Boolean.getInstance(o, false).isTrue();
                break;
            case 3:
                onlySomeReasons = new ReasonFlags(ReasonFlags.getInstance(o, false));
                break;
            case 4:
                indirectCRL = ASN1Boolean.getInstance(o, false).isTrue();
                break;
            case 5:
                onlyContainsAttributeCerts = ASN1Boolean.getInstance(o, false).isTrue();
                break;
            default:
                throw new IllegalArgumentException(
                        "unknown tag in IssuingDistributionPoint");
            }
        }
    }

    public boolean onlyContainsUserCerts()
    {
        return onlyContainsUserCerts;
    }

    public boolean onlyContainsCACerts()
    {
        return onlyContainsCACerts;
    }

    public boolean isIndirectCRL()
    {
        return indirectCRL;
    }

    public boolean onlyContainsAttributeCerts()
    {
        return onlyContainsAttributeCerts;
    }

    /**
     * @return Returns the distributionPoint.
     */
    public DistributionPointName getDistributionPoint()
    {
        return distributionPoint;
    }

    /**
     * @return Returns the onlySomeReasons.
     */
    public ReasonFlags getOnlySomeReasons()
    {
        return onlySomeReasons;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }

    public String toString()
    {
        String       sep = System.getProperty("line.separator");
        StringBuffer buf = new StringBuffer();

        buf.append("IssuingDistributionPoint: [");
        buf.append(sep);
        if (distributionPoint != null)
        {
            appendObject(buf, sep, "distributionPoint", distributionPoint.toString());
        }
        if (onlyContainsUserCerts)
        {
            appendObject(buf, sep, "onlyContainsUserCerts", booleanToString(onlyContainsUserCerts));
        }
        if (onlyContainsCACerts)
        {
            appendObject(buf, sep, "onlyContainsCACerts", booleanToString(onlyContainsCACerts));
        }
        if (onlySomeReasons != null)
        {
            appendObject(buf, sep, "onlySomeReasons", onlySomeReasons.toString());
        }
        if (onlyContainsAttributeCerts)
        {
            appendObject(buf, sep, "onlyContainsAttributeCerts", booleanToString(onlyContainsAttributeCerts));
        }
        if (indirectCRL)
        {
            appendObject(buf, sep, "indirectCRL", booleanToString(indirectCRL));
        }
        buf.append("]");
        buf.append(sep);
        return buf.toString();
    }

    private void appendObject(StringBuffer buf, String sep, String name, String value)
    {
        String       indent = "    ";

        buf.append(indent);
        buf.append(name);
        buf.append(":");
        buf.append(sep);
        buf.append(indent);
        buf.append(indent);
        buf.append(value);
        buf.append(sep);
    }

    private String booleanToString(boolean value)
    {
        return value ? "true" : "false";
    }
}
