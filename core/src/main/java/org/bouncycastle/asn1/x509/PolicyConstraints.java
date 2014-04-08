package org.bouncycastle.asn1.x509;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * PKIX RFC 5280
 * <pre>
 * id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }
 *
 * PolicyConstraints ::= SEQUENCE {
 *      requireExplicitPolicy           [0] SkipCerts OPTIONAL,
 *      inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
 *
 * SkipCerts ::= INTEGER (0..MAX)
 * </pre>
 */
public class PolicyConstraints
    extends ASN1Object
{
    private BigInteger requireExplicitPolicyMapping;
    private BigInteger inhibitPolicyMapping;

    public PolicyConstraints(BigInteger requireExplicitPolicyMapping, BigInteger inhibitPolicyMapping)
    {
        this.requireExplicitPolicyMapping = requireExplicitPolicyMapping;
        this.inhibitPolicyMapping = inhibitPolicyMapping;
    }

    private PolicyConstraints(ASN1Sequence seq)
    {
        for (int i = 0; i != seq.size(); i++)
        {
            ASN1TaggedObject to = ASN1TaggedObject.getInstance(seq.getObjectAt(i));

            if (to.getTagNo() == 0)
            {
                requireExplicitPolicyMapping = ASN1Integer.getInstance(to, false).getValue();
            }
            else if (to.getTagNo() == 1)
            {
                inhibitPolicyMapping = ASN1Integer.getInstance(to, false).getValue();
            }
            else
            {
                throw new IllegalArgumentException("Unknown tag encountered.");
            }
        }
    }

    public static PolicyConstraints getInstance(
        Object  obj)
    {
        if (obj instanceof PolicyConstraints)
        {
            return (PolicyConstraints)obj;
        }

        if (obj != null)
        {
            return new PolicyConstraints(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static PolicyConstraints fromExtensions(Extensions extensions)
    {
        return PolicyConstraints.getInstance(extensions.getExtensionParsedValue(Extension.policyConstraints));
    }

    public BigInteger getRequireExplicitPolicyMapping()
    {
        return requireExplicitPolicyMapping;
    }

    public BigInteger getInhibitPolicyMapping()
    {
        return inhibitPolicyMapping;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (requireExplicitPolicyMapping != null)
        {
            v.add(new DERTaggedObject(0, new ASN1Integer(requireExplicitPolicyMapping)));
        }

        if (inhibitPolicyMapping != null)
        {
            v.add(new DERTaggedObject(1, new ASN1Integer(inhibitPolicyMapping)));
        }

        return new DERSequence(v);
    }
}
