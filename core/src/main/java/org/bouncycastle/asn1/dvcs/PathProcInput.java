package org.bouncycastle.asn1.dvcs;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.PolicyInformation;

/**
 * <pre>
 *     PathProcInput ::= SEQUENCE {
 *         acceptablePolicySet          SEQUENCE SIZE (1..MAX) OF
 *                                         PolicyInformation,
 *         inhibitPolicyMapping         BOOLEAN DEFAULT FALSE,
 *         explicitPolicyReqd           [0] BOOLEAN DEFAULT FALSE ,
 *         inhibitAnyPolicy             [1] BOOLEAN DEFAULT FALSE
 *     }
 * </pre>
 */
public class PathProcInput
    extends ASN1Object
{

    private PolicyInformation[] acceptablePolicySet;
    private boolean inhibitPolicyMapping = false;
    private boolean explicitPolicyReqd = false;
    private boolean inhibitAnyPolicy = false;

    public PathProcInput(PolicyInformation[] acceptablePolicySet)
    {
        this.acceptablePolicySet = acceptablePolicySet;
    }

    public PathProcInput(PolicyInformation[] acceptablePolicySet, boolean inhibitPolicyMapping, boolean explicitPolicyReqd, boolean inhibitAnyPolicy)
    {
        this.acceptablePolicySet = acceptablePolicySet;
        this.inhibitPolicyMapping = inhibitPolicyMapping;
        this.explicitPolicyReqd = explicitPolicyReqd;
        this.inhibitAnyPolicy = inhibitAnyPolicy;
    }

    private static PolicyInformation[] fromSequence(ASN1Sequence seq)
    {
        PolicyInformation[] tmp = new PolicyInformation[seq.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = PolicyInformation.getInstance(seq.getObjectAt(i));
        }

        return tmp;
    }

    public static PathProcInput getInstance(Object obj)
    {
        if (obj instanceof PathProcInput)
        {
            return (PathProcInput)obj;
        }
        else if (obj != null)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(obj);
            ASN1Sequence policies = ASN1Sequence.getInstance(seq.getObjectAt(0));
            PathProcInput result = new PathProcInput(fromSequence(policies));

            for (int i = 1; i < seq.size(); i++)
            {
                Object o = seq.getObjectAt(i);

                if (o instanceof ASN1Boolean)
                {
                    ASN1Boolean x = ASN1Boolean.getInstance(o);
                    result.setInhibitPolicyMapping(x.isTrue());
                }
                else if (o instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject t = ASN1TaggedObject.getInstance(o);
                    ASN1Boolean x;
                    switch (t.getTagNo())
                    {
                    case 0:
                        x = ASN1Boolean.getInstance(t, false);
                        result.setExplicitPolicyReqd(x.isTrue());
                        break;
                    case 1:
                        x = ASN1Boolean.getInstance(t, false);
                        result.setInhibitAnyPolicy(x.isTrue());
                    }
                }
            }
            return result;
        }

        return null;
    }

    public static PathProcInput getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        ASN1EncodableVector pV = new ASN1EncodableVector();

        for (int i = 0; i != acceptablePolicySet.length; i++)
        {
            pV.add(acceptablePolicySet[i]);
        }

        v.add(new DERSequence(pV));

        if (inhibitPolicyMapping)
        {
            v.add(new ASN1Boolean(inhibitPolicyMapping));
        }
        if (explicitPolicyReqd)
        {
            v.add(new DERTaggedObject(false, 0, new ASN1Boolean(explicitPolicyReqd)));
        }
        if (inhibitAnyPolicy)
        {
            v.add(new DERTaggedObject(false, 1, new ASN1Boolean(inhibitAnyPolicy)));
        }

        return new DERSequence(v);
    }

    public String toString()
    {
        return "PathProcInput: {\n" +
            "acceptablePolicySet: " + acceptablePolicySet + "\n" +
            "inhibitPolicyMapping: " + inhibitPolicyMapping + "\n" +
            "explicitPolicyReqd: " + explicitPolicyReqd + "\n" +
            "inhibitAnyPolicy: " + inhibitAnyPolicy + "\n" +
            "}\n";
    }

    public PolicyInformation[] getAcceptablePolicySet()
    {
        return acceptablePolicySet;
    }

    public boolean isInhibitPolicyMapping()
    {
        return inhibitPolicyMapping;
    }

    private void setInhibitPolicyMapping(boolean inhibitPolicyMapping)
    {
        this.inhibitPolicyMapping = inhibitPolicyMapping;
    }

    public boolean isExplicitPolicyReqd()
    {
        return explicitPolicyReqd;
    }

    private void setExplicitPolicyReqd(boolean explicitPolicyReqd)
    {
        this.explicitPolicyReqd = explicitPolicyReqd;
    }

    public boolean isInhibitAnyPolicy()
    {
        return inhibitAnyPolicy;
    }

    private void setInhibitAnyPolicy(boolean inhibitAnyPolicy)
    {
        this.inhibitAnyPolicy = inhibitAnyPolicy;
    }
}
