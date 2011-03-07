package com.google.bitcoin.bouncycastle.asn1.x509;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.DERTaggedObject;

/**
 * The Holder object.
 * <p>
 * For an v2 attribute certificate this is:
 * 
 * <pre>
 *            Holder ::= SEQUENCE {
 *                  baseCertificateID   [0] IssuerSerial OPTIONAL,
 *                           -- the issuer and serial number of
 *                           -- the holder's Public Key Certificate
 *                  entityName          [1] GeneralNames OPTIONAL,
 *                           -- the name of the claimant or role
 *                  objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
 *                           -- used to directly authenticate the holder,
 *                           -- for example, an executable
 *            }
 * </pre>
 * 
 * <p>
 * For an v1 attribute certificate this is:
 * 
 * <pre>
 *         subject CHOICE {
 *          baseCertificateID [0] IssuerSerial,
 *          -- associated with a Public Key Certificate
 *          subjectName [1] GeneralNames },
 *          -- associated with a name
 * </pre>
 */
public class Holder
    extends ASN1Encodable
{
    IssuerSerial baseCertificateID;

    GeneralNames entityName;

    ObjectDigestInfo objectDigestInfo;

    private int version = 1;

    public static Holder getInstance(Object obj)
    {
        if (obj instanceof Holder)
        {
            return (Holder)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new Holder((ASN1Sequence)obj);
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            return new Holder((ASN1TaggedObject)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    /**
     * Constructor for a holder for an v1 attribute certificate.
     * 
     * @param tagObj The ASN.1 tagged holder object.
     */
    public Holder(ASN1TaggedObject tagObj)
    {
        switch (tagObj.getTagNo())
        {
        case 0:
            baseCertificateID = IssuerSerial.getInstance(tagObj, false);
            break;
        case 1:
            entityName = GeneralNames.getInstance(tagObj, false);
            break;
        default:
            throw new IllegalArgumentException("unknown tag in Holder");
        }
        version = 0;
    }

    /**
     * Constructor for a holder for an v2 attribute certificate. *
     * 
     * @param seq The ASN.1 sequence.
     */
    public Holder(ASN1Sequence seq)
    {
        if (seq.size() > 3)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }

        for (int i = 0; i != seq.size(); i++)
        {
            ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(seq
                .getObjectAt(i));

            switch (tObj.getTagNo())
            {
            case 0:
                baseCertificateID = IssuerSerial.getInstance(tObj, false);
                break;
            case 1:
                entityName = GeneralNames.getInstance(tObj, false);
                break;
            case 2:
                objectDigestInfo = ObjectDigestInfo.getInstance(tObj, false);
                break;
            default:
                throw new IllegalArgumentException("unknown tag in Holder");
            }
        }
        version = 1;
    }

    public Holder(IssuerSerial baseCertificateID)
    {
        this.baseCertificateID = baseCertificateID;
    }

    /**
     * Constructs a holder from a IssuerSerial.
     * @param baseCertificateID The IssuerSerial.
     * @param version The version of the attribute certificate. 
     */
    public Holder(IssuerSerial baseCertificateID, int version)
    {
        this.baseCertificateID = baseCertificateID;
        this.version = version;
    }
    
    /**
     * Returns 1 for v2 attribute certificates or 0 for v1 attribute
     * certificates. 
     * @return The version of the attribute certificate.
     */
    public int getVersion()
    {
        return version;
    }

    /**
     * Constructs a holder with an entityName for v2 attribute certificates or
     * with a subjectName for v1 attribute certificates.
     * 
     * @param entityName The entity or subject name.
     */
    public Holder(GeneralNames entityName)
    {
        this.entityName = entityName;
    }

    /**
     * Constructs a holder with an entityName for v2 attribute certificates or
     * with a subjectName for v1 attribute certificates.
     * 
     * @param entityName The entity or subject name.
     * @param version The version of the attribute certificate. 
     */
    public Holder(GeneralNames entityName, int version)
    {
        this.entityName = entityName;
        this.version = version;
    }
    
    /**
     * Constructs a holder from an object digest info.
     * 
     * @param objectDigestInfo The object digest info object.
     */
    public Holder(ObjectDigestInfo objectDigestInfo)
    {
        this.objectDigestInfo = objectDigestInfo;
    }

    public IssuerSerial getBaseCertificateID()
    {
        return baseCertificateID;
    }

    /**
     * Returns the entityName for an v2 attribute certificate or the subjectName
     * for an v1 attribute certificate.
     * 
     * @return The entityname or subjectname.
     */
    public GeneralNames getEntityName()
    {
        return entityName;
    }

    public ObjectDigestInfo getObjectDigestInfo()
    {
        return objectDigestInfo;
    }

    public DERObject toASN1Object()
    {
        if (version == 1)
        {
            ASN1EncodableVector v = new ASN1EncodableVector();

            if (baseCertificateID != null)
            {
                v.add(new DERTaggedObject(false, 0, baseCertificateID));
            }

            if (entityName != null)
            {
                v.add(new DERTaggedObject(false, 1, entityName));
            }

            if (objectDigestInfo != null)
            {
                v.add(new DERTaggedObject(false, 2, objectDigestInfo));
            }

            return new DERSequence(v);
        }
        else
        {
            if (entityName != null)
            {
                return new DERTaggedObject(false, 1, entityName);
            }
            else
            {
                return new DERTaggedObject(false, 0, baseCertificateID);
            }
        }
    }
}
