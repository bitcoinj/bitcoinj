package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

public class POPODecKeyChallContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private POPODecKeyChallContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static POPODecKeyChallContent getInstance(Object o)
    {
        if (o instanceof POPODecKeyChallContent)
        {
            return (POPODecKeyChallContent)o;
        }

        if (o != null)
        {
            return new POPODecKeyChallContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public Challenge[] toChallengeArray()
    {
        Challenge[] result = new Challenge[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = Challenge.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * POPODecKeyChallContent ::= SEQUENCE OF Challenge
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
