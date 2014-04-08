package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public class POPOSigningKeyInput
    extends ASN1Object
{
    private GeneralName sender;
    private PKMACValue publicKeyMAC;
    private SubjectPublicKeyInfo publicKey;

    private POPOSigningKeyInput(ASN1Sequence seq)
    {
        ASN1Encodable authInfo = (ASN1Encodable)seq.getObjectAt(0);

        if (authInfo instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagObj = (ASN1TaggedObject)authInfo;
            if (tagObj.getTagNo() != 0)
            {
                throw new IllegalArgumentException(
                    "Unknown authInfo tag: " + tagObj.getTagNo());
            }
            sender = GeneralName.getInstance(tagObj.getObject());
        }
        else
        {
            publicKeyMAC = PKMACValue.getInstance(authInfo);
        }

        publicKey = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(1));
    }

    public static POPOSigningKeyInput getInstance(Object o)
    {
        if (o instanceof POPOSigningKeyInput)
        {
            return (POPOSigningKeyInput)o;
        }

        if (o != null)
        {
            return new POPOSigningKeyInput(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     *  Creates a new POPOSigningKeyInput with sender name as authInfo.
     */
    public POPOSigningKeyInput(
        GeneralName sender,
        SubjectPublicKeyInfo spki)
    {
        this.sender = sender;
        this.publicKey = spki;
    }

    /**
     * Creates a new POPOSigningKeyInput using password-based MAC.
     */
    public POPOSigningKeyInput(
        PKMACValue pkmac,
        SubjectPublicKeyInfo spki)
    {
        this.publicKeyMAC = pkmac;
        this.publicKey = spki;
    }

    /**
     * Returns the sender field, or null if authInfo is publicKeyMAC
     */
    public GeneralName getSender()
    {
        return sender;
    }

    /**
     * Returns the publicKeyMAC field, or null if authInfo is sender
     */
    public PKMACValue getPublicKeyMAC()
    {
        return publicKeyMAC;
    }

    public SubjectPublicKeyInfo getPublicKey()
    {
        return publicKey;
    }

    /**
     * <pre>
     * POPOSigningKeyInput ::= SEQUENCE {
     *        authInfo             CHOICE {
     *                                 sender              [0] GeneralName,
     *                                 -- used only if an authenticated identity has been
     *                                 -- established for the sender (e.g., a DN from a
     *                                 -- previously-issued and currently-valid certificate
     *                                 publicKeyMAC        PKMACValue },
     *                                 -- used if no authenticated GeneralName currently exists for
     *                                 -- the sender; publicKeyMAC contains a password-based MAC
     *                                 -- on the DER-encoded value of publicKey
     *        publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (sender != null)
        {
            v.add(new DERTaggedObject(false, 0, sender));
        }
        else
        {
            v.add(publicKeyMAC);
        }

        v.add(publicKey);

        return new DERSequence(v);
    }
}
