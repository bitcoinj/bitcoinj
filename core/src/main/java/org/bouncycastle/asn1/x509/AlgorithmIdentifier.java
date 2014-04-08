package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;

public class AlgorithmIdentifier
    extends ASN1Object
{
    private ASN1ObjectIdentifier objectId;
    private ASN1Encodable       parameters;
    private boolean             parametersDefined = false;

    public static AlgorithmIdentifier getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    public static AlgorithmIdentifier getInstance(
        Object  obj)
    {
        if (obj== null || obj instanceof AlgorithmIdentifier)
        {
            return (AlgorithmIdentifier)obj;
        }

        // TODO: delete
        if (obj instanceof ASN1ObjectIdentifier)
        {
            return new AlgorithmIdentifier((ASN1ObjectIdentifier)obj);
        }

        // TODO: delete
        if (obj instanceof String)
        {
            return new AlgorithmIdentifier((String)obj);
        }

        return new AlgorithmIdentifier(ASN1Sequence.getInstance(obj));
    }

    public AlgorithmIdentifier(
        ASN1ObjectIdentifier     objectId)
    {
        this.objectId = objectId;
    }

    /**
     * @deprecated use ASN1ObjectIdentifier
     * @param objectId
     */
    public AlgorithmIdentifier(
        String     objectId)
    {
        this.objectId = new ASN1ObjectIdentifier(objectId);
    }

    public AlgorithmIdentifier(
        ASN1ObjectIdentifier     objectId,
        ASN1Encodable           parameters)
    {
        parametersDefined = true;
        this.objectId = objectId;
        this.parameters = parameters;
    }

    /**
     * @deprecated use AlgorithmIdentifier.getInstance()
     * @param seq
     */
    public AlgorithmIdentifier(
        ASN1Sequence   seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }
        
        objectId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

        if (seq.size() == 2)
        {
            parametersDefined = true;
            parameters = seq.getObjectAt(1);
        }
        else
        {
            parameters = null;
        }
    }

    public ASN1ObjectIdentifier getAlgorithm()
    {
        return new ASN1ObjectIdentifier(objectId.getId());
    }

    /**
     * @deprecated use getAlgorithm
     * @return
     */
    public ASN1ObjectIdentifier getObjectId()
    {
        return objectId;
    }

    public ASN1Encodable getParameters()
    {
        return parameters;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *      AlgorithmIdentifier ::= SEQUENCE {
     *                            algorithm OBJECT IDENTIFIER,
     *                            parameters ANY DEFINED BY algorithm OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(objectId);

        if (parametersDefined)
        {
            if (parameters != null)
            {
                v.add(parameters);
            }
            else
            {
                v.add(DERNull.INSTANCE);
            }
        }

        return new DERSequence(v);
    }
}
