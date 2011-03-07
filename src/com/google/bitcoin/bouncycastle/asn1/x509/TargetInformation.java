package com.google.bitcoin.bouncycastle.asn1.x509;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;

import java.util.Enumeration;

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
    extends ASN1Encodable
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
            return (TargetInformation) obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new TargetInformation((ASN1Sequence) obj);
        }

        throw new IllegalArgumentException("unknown object in factory: "
            + obj.getClass());
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
     * {@link com.google.bitcoin.bouncycastle.asn1.ASN1Sequence} the encoding is kept.
     * 
     * @return a DERObject
     */
    public DERObject toASN1Object()
    {
        return targets;
    }
}
