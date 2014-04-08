package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class POPOSigningKey
    extends ASN1Object
{
    private POPOSigningKeyInput poposkInput;
    private AlgorithmIdentifier algorithmIdentifier;
    private DERBitString signature;

    private POPOSigningKey(ASN1Sequence seq)
    {
        int index = 0;

        if (seq.getObjectAt(index) instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagObj
                = (ASN1TaggedObject)seq.getObjectAt(index++);
            if (tagObj.getTagNo() != 0)
            {
                throw new IllegalArgumentException(
                    "Unknown POPOSigningKeyInput tag: " + tagObj.getTagNo());
            }
            poposkInput = POPOSigningKeyInput.getInstance(tagObj.getObject());
        }
        algorithmIdentifier = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));
        signature = DERBitString.getInstance(seq.getObjectAt(index));
    }

    public static POPOSigningKey getInstance(Object o)
    {
        if (o instanceof POPOSigningKey)
        {
            return (POPOSigningKey)o;
        }

        if (o != null)
        {
            return new POPOSigningKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static POPOSigningKey getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Creates a new Proof of Possession object for a signing key.
     *
     * @param poposkIn  the POPOSigningKeyInput structure, or null if the
     *                  CertTemplate includes both subject and publicKey values.
     * @param aid       the AlgorithmIdentifier used to sign the proof of possession.
     * @param signature a signature over the DER-encoded value of poposkIn,
     *                  or the DER-encoded value of certReq if poposkIn is null.
     */
    public POPOSigningKey(
        POPOSigningKeyInput poposkIn,
        AlgorithmIdentifier aid,
        DERBitString signature)
    {
        this.poposkInput = poposkIn;
        this.algorithmIdentifier = aid;
        this.signature = signature;
    }

    public POPOSigningKeyInput getPoposkInput()
    {
        return poposkInput;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmIdentifier;
    }

    public DERBitString getSignature()
    {
        return signature;
    }

    /**
     * <pre>
     * POPOSigningKey ::= SEQUENCE {
     *                      poposkInput           [0] POPOSigningKeyInput OPTIONAL,
     *                      algorithmIdentifier   AlgorithmIdentifier,
     *                      signature             BIT STRING }
     *  -- The signature (using "algorithmIdentifier") is on the
     *  -- DER-encoded value of poposkInput.  NOTE: If the CertReqMsg
     *  -- certReq CertTemplate contains the subject and publicKey values,
     *  -- then poposkInput MUST be omitted and the signature MUST be
     *  -- computed on the DER-encoded value of CertReqMsg certReq.  If
     *  -- the CertReqMsg certReq CertTemplate does not contain the public
     *  -- key and subject values, then poposkInput MUST be present and
     *  -- MUST be signed.  This strategy ensures that the public key is
     *  -- not present in both the poposkInput and CertReqMsg certReq
     *  -- CertTemplate fields.
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (poposkInput != null)
        {
            v.add(new DERTaggedObject(false, 0, poposkInput));
        }

        v.add(algorithmIdentifier);
        v.add(signature);

        return new DERSequence(v);
    }
}
