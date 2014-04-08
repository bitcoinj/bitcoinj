package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Password-based MAC value for use with POPOSigningKeyInput.
 */
public class PKMACValue
    extends ASN1Object
{
    private AlgorithmIdentifier  algId;
    private DERBitString        value;

    private PKMACValue(ASN1Sequence seq)
    {
        algId = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        value = DERBitString.getInstance(seq.getObjectAt(1));
    }

    public static PKMACValue getInstance(Object o)
    {
        if (o instanceof PKMACValue)
        {
            return (PKMACValue)o;
        }

        if (o != null)
        {
            return new PKMACValue(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static PKMACValue getInstance(ASN1TaggedObject obj, boolean isExplicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, isExplicit));
    }

    /**
     * Creates a new PKMACValue.
     * @param params parameters for password-based MAC
     * @param value MAC of the DER-encoded SubjectPublicKeyInfo
     */
    public PKMACValue(
        PBMParameter params,
        DERBitString value)
    {
        this(new AlgorithmIdentifier(
                    CMPObjectIdentifiers.passwordBasedMac, params), value);
    }

    /**
     * Creates a new PKMACValue.
     * @param aid CMPObjectIdentifiers.passwordBasedMAC, with PBMParameter
     * @param value MAC of the DER-encoded SubjectPublicKeyInfo
     */
    public PKMACValue(
        AlgorithmIdentifier aid,
        DERBitString value)
    {
        this.algId = aid;
        this.value = value;
    }

    public AlgorithmIdentifier getAlgId()
    {
        return algId;
    }

    public DERBitString getValue()
    {
        return value;
    }

    /**
     * <pre>
     * PKMACValue ::= SEQUENCE {
     *      algId  AlgorithmIdentifier,
     *      -- algorithm value shall be PasswordBasedMac 1.2.840.113533.7.66.13
     *      -- parameter value is PBMParameter
     *      value  BIT STRING }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(algId);
        v.add(value);

        return new DERSequence(v);
    }
}
