package org.bouncycastle.asn1.x509;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * Target information extension for attributes certificates according to RFC
 * 3281.
 * 
 * <pre>
 *           SEQUENCE OF Targets
 * </pre>
 * 
 */
public class TargetInformation
    extends ASN1Object
{
    private ASN1Sequence targets;

    /**
     * Creates an instance of a TargetInformation from the given object.
     * <p>
     * <code>obj</code> can be a TargetInformation or a {@link ASN1Sequence}
     * 
     * @param obj The object.
     * @return A TargetInformation instance.
     * @throws IllegalArgumentException if the given object cannot be
     *             interpreted as TargetInformation.
     */
    public static TargetInformation getInstance(Object obj)
    {
        if (obj instanceof TargetInformation)
        {
            return (TargetInformation)obj;
        }
        else if (obj != null)
        {
            return new TargetInformation(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Constructor from a ASN1Sequence.
     * 
     * @param seq The ASN1Sequence.
     * @throws IllegalArgumentException if the sequence does not contain
     *             correctly encoded Targets elements.
     */
    private TargetInformation(ASN1Sequence seq)
    {
        targets = seq;
    }

    /**
     * Returns the targets in this target information extension.
     * 
     * @return Returns the targets.
     */
    public Targets[] getTargetsObjects()
    {
        Targets[] copy = new Targets[targets.size()];
        int count = 0;
        for (Enumeration e = targets.getObjects(); e.hasMoreElements();)
        {
            copy[count++] = Targets.getInstance(e.nextElement());
        }
        return copy;
    }

    /**
     * Constructs a target information from a single targets element. 
     * According to RFC 3281 only one targets element must be produced.
     * 
     * @param targets A Targets instance.
     */
    public TargetInformation(Targets targets)
    {
        this.targets = new DERSequence(targets);
    }

    /**
     * According to RFC 3281 only one targets element must be produced. If
     * multiple targets are given they must be merged in
     * into one targets element.
     *
     * @param targets An array with {@link Targets}.
     */
    public TargetInformation(Target[] targets)
    {
        this(new Targets(targets));
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * 
     * Returns:
     * 
     * <pre>
     *          SEQUENCE OF Targets
     * </pre>
     * 
     * <p>
     * According to RFC 3281 only one targets element must be produced. If
     * multiple targets are given in the constructor they are merged into one
     * targets element. If this was produced from a
     * {@link org.bouncycastle.asn1.ASN1Sequence} the encoding is kept.
     * 
     * @return a ASN1Primitive
     */
    public ASN1Primitive toASN1Primitive()
    {
        return targets;
    }
}
