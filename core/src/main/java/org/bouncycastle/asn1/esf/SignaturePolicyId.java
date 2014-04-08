package org.bouncycastle.asn1.esf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class SignaturePolicyId
    extends ASN1Object
{
    private ASN1ObjectIdentifier  sigPolicyId;
    private OtherHashAlgAndValue sigPolicyHash;
    private SigPolicyQualifiers  sigPolicyQualifiers;


    public static SignaturePolicyId getInstance(
        Object obj)
    {
        if (obj instanceof SignaturePolicyId)
        {
            return (SignaturePolicyId)obj;
        }
        else if (obj != null)
        {
            return new SignaturePolicyId(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private SignaturePolicyId(
        ASN1Sequence seq)
    {
        if (seq.size() != 2 && seq.size() != 3)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        sigPolicyId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        sigPolicyHash = OtherHashAlgAndValue.getInstance(seq.getObjectAt(1));

        if (seq.size() == 3)
        {
            sigPolicyQualifiers = SigPolicyQualifiers.getInstance(seq.getObjectAt(2));
        }
    }

    public SignaturePolicyId(
        ASN1ObjectIdentifier   sigPolicyIdentifier,
        OtherHashAlgAndValue  sigPolicyHash)
    {
        this(sigPolicyIdentifier, sigPolicyHash, null);
    }

    public SignaturePolicyId(
        ASN1ObjectIdentifier   sigPolicyId,
        OtherHashAlgAndValue  sigPolicyHash,
        SigPolicyQualifiers   sigPolicyQualifiers)
    {
        this.sigPolicyId = sigPolicyId;
        this.sigPolicyHash = sigPolicyHash;
        this.sigPolicyQualifiers = sigPolicyQualifiers;
    }

    public ASN1ObjectIdentifier getSigPolicyId()
    {
        return new ASN1ObjectIdentifier(sigPolicyId.getId());
    }

    public OtherHashAlgAndValue getSigPolicyHash()
    {
        return sigPolicyHash;
    }

    public SigPolicyQualifiers getSigPolicyQualifiers()
    {
        return sigPolicyQualifiers;
    }

    /**
     * <pre>
     * SignaturePolicyId ::= SEQUENCE {
     *     sigPolicyId SigPolicyId,
     *     sigPolicyHash SigPolicyHash,
     *     sigPolicyQualifiers SEQUENCE SIZE (1..MAX) OF SigPolicyQualifierInfo OPTIONAL}
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(sigPolicyId);
        v.add(sigPolicyHash);
        if (sigPolicyQualifiers != null)
        {
            v.add(sigPolicyQualifiers);
        }

        return new DERSequence(v);
    }
}
