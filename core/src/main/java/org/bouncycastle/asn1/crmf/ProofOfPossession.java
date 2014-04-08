package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERTaggedObject;

public class ProofOfPossession
    extends ASN1Object
    implements ASN1Choice
{
    public static final int TYPE_RA_VERIFIED = 0;
    public static final int TYPE_SIGNING_KEY = 1;
    public static final int TYPE_KEY_ENCIPHERMENT = 2;
    public static final int TYPE_KEY_AGREEMENT = 3;

    private int tagNo;
    private ASN1Encodable obj;

    private ProofOfPossession(ASN1TaggedObject tagged)
    {
        tagNo = tagged.getTagNo();
        switch (tagNo)
        {
        case 0:
            obj = DERNull.INSTANCE;
            break;
        case 1:
            obj = POPOSigningKey.getInstance(tagged, false);
            break;
        case 2:
        case 3:
            obj = POPOPrivKey.getInstance(tagged, true);
            break;
        default:
            throw new IllegalArgumentException("unknown tag: " + tagNo);
        }
    }

    public static ProofOfPossession getInstance(Object o)
    {
        if (o == null || o instanceof ProofOfPossession)
        {
            return (ProofOfPossession)o;
        }

        if (o instanceof ASN1TaggedObject)
        {
            return new ProofOfPossession((ASN1TaggedObject)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    /** Creates a ProofOfPossession with type raVerified. */
    public ProofOfPossession()
    {
        tagNo = TYPE_RA_VERIFIED;
        obj = DERNull.INSTANCE;
    }

    /** Creates a ProofOfPossession for a signing key. */
    public ProofOfPossession(POPOSigningKey poposk)
    {
        tagNo = TYPE_SIGNING_KEY;
        obj = poposk;
    }

    /**
     * Creates a ProofOfPossession for key encipherment or agreement.
     * @param type one of TYPE_KEY_ENCIPHERMENT or TYPE_KEY_AGREEMENT
     */
    public ProofOfPossession(int type, POPOPrivKey privkey)
    {
        tagNo = type;
        obj = privkey;
    }

    public int getType()
    {
        return tagNo;
    }

    public ASN1Encodable getObject()
    {
        return obj;
    }

    /**
     * <pre>
     * ProofOfPossession ::= CHOICE {
     *                           raVerified        [0] NULL,
     *                           -- used if the RA has already verified that the requester is in
     *                           -- possession of the private key
     *                           signature         [1] POPOSigningKey,
     *                           keyEncipherment   [2] POPOPrivKey,
     *                           keyAgreement      [3] POPOPrivKey }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(false, tagNo, obj);
    }
}
