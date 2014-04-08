package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;

/**
 * ObjectDigestInfo ASN.1 structure used in v2 attribute certificates.
 * 
 * <pre>
 *  
 *    ObjectDigestInfo ::= SEQUENCE {
 *         digestedObjectType  ENUMERATED {
 *                 publicKey            (0),
 *                 publicKeyCert        (1),
 *                 otherObjectTypes     (2) },
 *                         -- otherObjectTypes MUST NOT
 *                         -- be used in this profile
 *         otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
 *         digestAlgorithm     AlgorithmIdentifier,
 *         objectDigest        BIT STRING
 *    }
 *   
 * </pre>
 * 
 */
public class ObjectDigestInfo
    extends ASN1Object
{
    /**
     * The public key is hashed.
     */
    public final static int publicKey = 0;

    /**
     * The public key certificate is hashed.
     */
    public final static int publicKeyCert = 1;

    /**
     * An other object is hashed.
     */
    public final static int otherObjectDigest = 2;

    ASN1Enumerated digestedObjectType;

    ASN1ObjectIdentifier otherObjectTypeID;

    AlgorithmIdentifier digestAlgorithm;

    DERBitString objectDigest;

    public static ObjectDigestInfo getInstance(
        Object obj)
    {
        if (obj instanceof ObjectDigestInfo)
        {
            return (ObjectDigestInfo)obj;
        }

        if (obj != null)
        {
            return new ObjectDigestInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static ObjectDigestInfo getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Constructor from given details.
     * <p>
     * If <code>digestedObjectType</code> is not {@link #publicKeyCert} or
     * {@link #publicKey} <code>otherObjectTypeID</code> must be given,
     * otherwise it is ignored.
     * 
     * @param digestedObjectType The digest object type.
     * @param otherObjectTypeID The object type ID for
     *            <code>otherObjectDigest</code>.
     * @param digestAlgorithm The algorithm identifier for the hash.
     * @param objectDigest The hash value.
     */
    public ObjectDigestInfo(
        int digestedObjectType,
        ASN1ObjectIdentifier otherObjectTypeID,
        AlgorithmIdentifier digestAlgorithm,
        byte[] objectDigest)
    {
        this.digestedObjectType = new ASN1Enumerated(digestedObjectType);
        if (digestedObjectType == otherObjectDigest)
        {
            this.otherObjectTypeID = otherObjectTypeID;
        }

        this.digestAlgorithm = digestAlgorithm;
        this.objectDigest = new DERBitString(objectDigest);
    }

    private ObjectDigestInfo(
        ASN1Sequence seq)
    {
        if (seq.size() > 4 || seq.size() < 3)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }

        digestedObjectType = ASN1Enumerated.getInstance(seq.getObjectAt(0));

        int offset = 0;

        if (seq.size() == 4)
        {
            otherObjectTypeID = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
            offset++;
        }

        digestAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1 + offset));

        objectDigest = DERBitString.getInstance(seq.getObjectAt(2 + offset));
    }

    public ASN1Enumerated getDigestedObjectType()
    {
        return digestedObjectType;
    }

    public ASN1ObjectIdentifier getOtherObjectTypeID()
    {
        return otherObjectTypeID;
    }

    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgorithm;
    }

    public DERBitString getObjectDigest()
    {
        return objectDigest;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * 
     * <pre>
     *  
     *    ObjectDigestInfo ::= SEQUENCE {
     *         digestedObjectType  ENUMERATED {
     *                 publicKey            (0),
     *                 publicKeyCert        (1),
     *                 otherObjectTypes     (2) },
     *                         -- otherObjectTypes MUST NOT
     *                         -- be used in this profile
     *         otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
     *         digestAlgorithm     AlgorithmIdentifier,
     *         objectDigest        BIT STRING
     *    }
     *   
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(digestedObjectType);

        if (otherObjectTypeID != null)
        {
            v.add(otherObjectTypeID);
        }

        v.add(digestAlgorithm);
        v.add(objectDigest);

        return new DERSequence(v);
    }
}
