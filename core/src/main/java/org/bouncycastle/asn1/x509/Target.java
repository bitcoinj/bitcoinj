package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * Target structure used in target information extension for attribute
 * certificates from RFC 3281.
 * 
 * <pre>
 *     Target  ::= CHOICE {
 *       targetName          [0] GeneralName,
 *       targetGroup         [1] GeneralName,
 *       targetCert          [2] TargetCert
 *     }
 * </pre>
 * 
 * <p>
 * The targetCert field is currently not supported and must not be used
 * according to RFC 3281.
 */
public class Target
    extends ASN1Object
    implements ASN1Choice
{
    public static final int targetName = 0;
    public static final int targetGroup = 1;

    private GeneralName targName;
    private GeneralName targGroup;

    /**
     * Creates an instance of a Target from the given object.
     * <p>
     * <code>obj</code> can be a Target or a {@link ASN1TaggedObject}
     * 
     * @param obj The object.
     * @return A Target instance.
     * @throws IllegalArgumentException if the given object cannot be
     *             interpreted as Target.
     */
    public static Target getInstance(Object obj)
    {
        if (obj == null || obj instanceof Target)
        {
            return (Target) obj;
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            return new Target((ASN1TaggedObject)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: "
            + obj.getClass());
    }

    /**
     * Constructor from ASN1TaggedObject.
     * 
     * @param tagObj The tagged object.
     * @throws IllegalArgumentException if the encoding is wrong.
     */
    private Target(ASN1TaggedObject tagObj)
    {
        switch (tagObj.getTagNo())
        {
        case targetName:     // GeneralName is already a choice so explicit
            targName = GeneralName.getInstance(tagObj, true);
            break;
        case targetGroup:
            targGroup = GeneralName.getInstance(tagObj, true);
            break;
        default:
            throw new IllegalArgumentException("unknown tag: " + tagObj.getTagNo());
        }
    }

    /**
     * Constructor from given details.
     * <p>
     * Exactly one of the parameters must be not <code>null</code>.
     *
     * @param type the choice type to apply to the name.
     * @param name the general name.
     * @throws IllegalArgumentException if type is invalid.
     */
    public Target(int type, GeneralName name)
    {
        this(new DERTaggedObject(type, name));
    }

    /**
     * @return Returns the targetGroup.
     */
    public GeneralName getTargetGroup()
    {
        return targGroup;
    }

    /**
     * @return Returns the targetName.
     */
    public GeneralName getTargetName()
    {
        return targName;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * 
     * Returns:
     * 
     * <pre>
     *     Target  ::= CHOICE {
     *       targetName          [0] GeneralName,
     *       targetGroup         [1] GeneralName,
     *       targetCert          [2] TargetCert
     *     }
     * </pre>
     * 
     * @return a ASN1Primitive
     */
    public ASN1Primitive toASN1Primitive()
    {
        // GeneralName is a choice already so most be explicitly tagged
        if (targName != null)
        {
            return new DERTaggedObject(true, 0, targName);
        }
        else
        {
            return new DERTaggedObject(true, 1, targGroup);
        }
    }
}
