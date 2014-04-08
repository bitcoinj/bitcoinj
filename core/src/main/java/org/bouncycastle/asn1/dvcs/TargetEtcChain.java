package org.bouncycastle.asn1.dvcs;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 *     TargetEtcChain ::= SEQUENCE {
 *         target                       CertEtcToken,
 *         chain                        SEQUENCE SIZE (1..MAX) OF
 *                                         CertEtcToken OPTIONAL,
 *         pathProcInput                [0] PathProcInput OPTIONAL
 *     }
 * </pre>
 */

public class TargetEtcChain
    extends ASN1Object
{
    private CertEtcToken target;
    private ASN1Sequence chain;
    private PathProcInput pathProcInput;

    public TargetEtcChain(CertEtcToken target)
    {
        this(target, null, null);
    }

    public TargetEtcChain(CertEtcToken target, CertEtcToken[] chain)
    {
        this(target, chain, null);
    }

    public TargetEtcChain(CertEtcToken target, PathProcInput pathProcInput)
    {
        this(target, null, pathProcInput);
    }

    public TargetEtcChain(CertEtcToken target, CertEtcToken[] chain, PathProcInput pathProcInput)
    {
        this.target = target;

        if (chain != null)
        {
            this.chain = new DERSequence(chain);
        }

        this.pathProcInput = pathProcInput;
    }

    private TargetEtcChain(ASN1Sequence seq)
    {
        int i = 0;
        ASN1Encodable obj = seq.getObjectAt(i++);
        this.target = CertEtcToken.getInstance(obj);

        try
        {
            obj = seq.getObjectAt(i++);
            this.chain = ASN1Sequence.getInstance(obj);
        }
        catch (IllegalArgumentException e)
        {
        }
        catch (IndexOutOfBoundsException e)
        {
            return;
        }

        try
        {
            obj = seq.getObjectAt(i++);
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(obj);
            switch (tagged.getTagNo())
            {
            case 0:
                this.pathProcInput = PathProcInput.getInstance(tagged, false);
                break;
            }
        }
        catch (IllegalArgumentException e)
        {
        }
        catch (IndexOutOfBoundsException e)
        {
        }
    }

    public static TargetEtcChain getInstance(Object obj)
    {
        if (obj instanceof TargetEtcChain)
        {
            return (TargetEtcChain)obj;
        }
        else if (obj != null)
        {
            return new TargetEtcChain(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static TargetEtcChain getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(target);
        if (chain != null)
        {
            v.add(chain);
        }
        if (pathProcInput != null)
        {
            v.add(new DERTaggedObject(false, 0, pathProcInput));
        }

        return new DERSequence(v);
    }

    public String toString()
    {
        StringBuffer s = new StringBuffer();
        s.append("TargetEtcChain {\n");
        s.append("target: " + target + "\n");
        if (chain != null)
        {
            s.append("chain: " + chain + "\n");
        }
        if (pathProcInput != null)
        {
            s.append("pathProcInput: " + pathProcInput + "\n");
        }
        s.append("}\n");
        return s.toString();
    }


    public CertEtcToken getTarget()
    {
        return target;
    }

    public CertEtcToken[] getChain()
    {
        if (chain != null)
        {
            return CertEtcToken.arrayFromSequence(chain);
        }

        return null;
    }

    private void setChain(ASN1Sequence chain)
    {
        this.chain = chain;
    }

    public PathProcInput getPathProcInput()
    {
        return pathProcInput;
    }

    private void setPathProcInput(PathProcInput pathProcInput)
    {
        this.pathProcInput = pathProcInput;
    }

    public static TargetEtcChain[] arrayFromSequence(ASN1Sequence seq)
    {
        TargetEtcChain[] tmp = new TargetEtcChain[seq.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = TargetEtcChain.getInstance(seq.getObjectAt(i));
        }

        return tmp;
    }
}
