package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;

/**
 * The SubjectKeyIdentifier object.
 * <pre>
 * SubjectKeyIdentifier::= OCTET STRING
 * </pre>
 */
public class SubjectKeyIdentifier
    extends ASN1Object
{
    private byte[] keyidentifier;

    public static SubjectKeyIdentifier getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1OctetString.getInstance(obj, explicit));
    }

    public static SubjectKeyIdentifier getInstance(
        Object obj)
    {
        if (obj instanceof SubjectKeyIdentifier)
        {
            return (SubjectKeyIdentifier)obj;
        }
        else if (obj != null)
        {
            return new SubjectKeyIdentifier(ASN1OctetString.getInstance(obj));
        }

        return null;
    }

    public static SubjectKeyIdentifier fromExtensions(Extensions extensions)
    {
        return SubjectKeyIdentifier.getInstance(extensions.getExtensionParsedValue(Extension.subjectKeyIdentifier));
    }

    public SubjectKeyIdentifier(
        byte[] keyid)
    {
        this.keyidentifier = keyid;
    }

    protected SubjectKeyIdentifier(
        ASN1OctetString keyid)
    {
        this.keyidentifier = keyid.getOctets();
    }

    public byte[] getKeyIdentifier()
    {
        return keyidentifier;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(keyidentifier);
    }


    /**
     * Calculates the keyidentifier using a SHA1 hash over the BIT STRING
     * from SubjectPublicKeyInfo as defined in RFC3280.
     *
     * @param spki the subject public key info.
     * @deprecated
     */
    public SubjectKeyIdentifier(
        SubjectPublicKeyInfo    spki)
    {
        this.keyidentifier = getDigest(spki);
    }

    /**
     * Return a RFC 3280 type 1 key identifier. As in:
     * <pre>
     * (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
     * value of the BIT STRING subjectPublicKey (excluding the tag,
     * length, and number of unused bits).
     * </pre>
     * @param keyInfo the key info object containing the subjectPublicKey field.
     * @return the key identifier.
     * @deprecated use org.bouncycastle.cert.X509ExtensionUtils.createSubjectKeyIdentifier
     */
    public static SubjectKeyIdentifier createSHA1KeyIdentifier(SubjectPublicKeyInfo keyInfo)
    {
        return new SubjectKeyIdentifier(keyInfo);
    }

    /**
     * Return a RFC 3280 type 2 key identifier. As in:
     * <pre>
     * (2) The keyIdentifier is composed of a four bit type field with
     * the value 0100 followed by the least significant 60 bits of the
     * SHA-1 hash of the value of the BIT STRING subjectPublicKey.
     * </pre>
     * @param keyInfo the key info object containing the subjectPublicKey field.
     * @return the key identifier.
     * @deprecated use org.bouncycastle.cert.X509ExtensionUtils.createTruncatedSubjectKeyIdentifier
     */
    public static SubjectKeyIdentifier createTruncatedSHA1KeyIdentifier(SubjectPublicKeyInfo keyInfo)
    {
        byte[] dig = getDigest(keyInfo);
        byte[] id = new byte[8];

        System.arraycopy(dig, dig.length - 8, id, 0, id.length);

        id[0] &= 0x0f;
        id[0] |= 0x40;
        
        return new SubjectKeyIdentifier(id);
    }

    private static byte[] getDigest(SubjectPublicKeyInfo spki)
    {
        Digest digest = new SHA1Digest();
        byte[]  resBuf = new byte[digest.getDigestSize()];

        byte[] bytes = spki.getPublicKeyData().getBytes();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);
        return resBuf;
    }
}
