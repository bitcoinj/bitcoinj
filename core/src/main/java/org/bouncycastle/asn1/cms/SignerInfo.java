package org.bouncycastle.asn1.cms;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-5.3">RFC 5652</a>:
 * Signature container per Signer, see {@link SignerIdentifier}.
 * <pre>
 * PKCS#7:
 *
 * SignerInfo ::= SEQUENCE {
 *     version                   Version,
 *     sid                       SignerIdentifier,
 *     digestAlgorithm           DigestAlgorithmIdentifier,
 *     authenticatedAttributes   [0] IMPLICIT Attributes OPTIONAL,
 *     digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *     encryptedDigest           EncryptedDigest,
 *     unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
 * }
 *
 * EncryptedDigest ::= OCTET STRING
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * DigestEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * -----------------------------------------
 *
 * RFC 5256:
 *
 * SignerInfo ::= SEQUENCE {
 *     version            CMSVersion,
 *     sid                SignerIdentifier,
 *     digestAlgorithm    DigestAlgorithmIdentifier,
 *     signedAttrs        [0] IMPLICIT SignedAttributes OPTIONAL,
 *     signatureAlgorithm SignatureAlgorithmIdentifier,
 *     signature          SignatureValue,
 *     unsignedAttrs      [1] IMPLICIT UnsignedAttributes OPTIONAL
 * }
 *
 * -- {@link SignerIdentifier} referenced certificates are at containing
 * -- {@link SignedData} certificates element.
 *
 * SignerIdentifier ::= CHOICE {
 *     issuerAndSerialNumber {@link IssuerAndSerialNumber},
 *     subjectKeyIdentifier  [0] SubjectKeyIdentifier }
 *
 * -- See {@link Attributes} for generalized SET OF {@link Attribute}
 *
 * SignedAttributes   ::= SET SIZE (1..MAX) OF Attribute
 * UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 * 
 * {@link Attribute} ::= SEQUENCE {
 *     attrType   OBJECT IDENTIFIER,
 *     attrValues SET OF AttributeValue }
 *
 * AttributeValue ::= ANY
 * 
 * SignatureValue ::= OCTET STRING
 * </pre>
 */
public class SignerInfo
    extends ASN1Object
{
    private ASN1Integer              version;
    private SignerIdentifier        sid;
    private AlgorithmIdentifier     digAlgorithm;
    private ASN1Set                 authenticatedAttributes;
    private AlgorithmIdentifier     digEncryptionAlgorithm;
    private ASN1OctetString         encryptedDigest;
    private ASN1Set                 unauthenticatedAttributes;

    /**
     * Return a SignerInfo object from the given input
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link SignerInfo} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with SignerInfo structure inside
     * </ul>
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static SignerInfo getInstance(
        Object  o)
        throws IllegalArgumentException
    {
        if (o instanceof SignerInfo)
        {
            return (SignerInfo)o;
        }
        else if (o != null)
        {
            return new SignerInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     *
     * @param sid
     * @param digAlgorithm            CMS knows as 'digestAlgorithm'
     * @param authenticatedAttributes CMS knows as 'signedAttrs'
     * @param digEncryptionAlgorithm  CMS knows as 'signatureAlgorithm'
     * @param encryptedDigest         CMS knows as 'signature'
     * @param unauthenticatedAttributes CMS knows as 'unsignedAttrs'
     */
    public SignerInfo(
        SignerIdentifier        sid,
        AlgorithmIdentifier     digAlgorithm,
        ASN1Set                 authenticatedAttributes,
        AlgorithmIdentifier     digEncryptionAlgorithm,
        ASN1OctetString         encryptedDigest,
        ASN1Set                 unauthenticatedAttributes)
    {
        if (sid.isTagged())
        {
            this.version = new ASN1Integer(3);
        }
        else
        {
            this.version = new ASN1Integer(1);
        }

        this.sid = sid;
        this.digAlgorithm = digAlgorithm;
        this.authenticatedAttributes = authenticatedAttributes;
        this.digEncryptionAlgorithm = digEncryptionAlgorithm;
        this.encryptedDigest = encryptedDigest;
        this.unauthenticatedAttributes = unauthenticatedAttributes;
    }

    /**
     *
     * @param sid
     * @param digAlgorithm            CMS knows as 'digestAlgorithm'
     * @param authenticatedAttributes CMS knows as 'signedAttrs'
     * @param digEncryptionAlgorithm  CMS knows as 'signatureAlgorithm'
     * @param encryptedDigest         CMS knows as 'signature'
     * @param unauthenticatedAttributes CMS knows as 'unsignedAttrs'
     */
    public SignerInfo(
        SignerIdentifier        sid,
        AlgorithmIdentifier     digAlgorithm,
        Attributes              authenticatedAttributes,
        AlgorithmIdentifier     digEncryptionAlgorithm,
        ASN1OctetString         encryptedDigest,
        Attributes              unauthenticatedAttributes)
    {
        if (sid.isTagged())
        {
            this.version = new ASN1Integer(3);
        }
        else
        {
            this.version = new ASN1Integer(1);
        }

        this.sid = sid;
        this.digAlgorithm = digAlgorithm;
        this.authenticatedAttributes = ASN1Set.getInstance(authenticatedAttributes);
        this.digEncryptionAlgorithm = digEncryptionAlgorithm;
        this.encryptedDigest = encryptedDigest;
        this.unauthenticatedAttributes = ASN1Set.getInstance(unauthenticatedAttributes);
    }

    /**
     * @deprecated use getInstance() method.
     */
    public SignerInfo(
        ASN1Sequence seq)
    {
        Enumeration     e = seq.getObjects();

        version = (ASN1Integer)e.nextElement();
        sid = SignerIdentifier.getInstance(e.nextElement());
        digAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());

        Object obj = e.nextElement();

        if (obj instanceof ASN1TaggedObject)
        {
            authenticatedAttributes = ASN1Set.getInstance((ASN1TaggedObject)obj, false);

            digEncryptionAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());
        }
        else
        {
            authenticatedAttributes = null;
            digEncryptionAlgorithm = AlgorithmIdentifier.getInstance(obj);
        }

        encryptedDigest = DEROctetString.getInstance(e.nextElement());

        if (e.hasMoreElements())
        {
            unauthenticatedAttributes = ASN1Set.getInstance((ASN1TaggedObject)e.nextElement(), false);
        }
        else
        {
            unauthenticatedAttributes = null;
        }
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public SignerIdentifier getSID()
    {
        return sid;
    }

    public ASN1Set getAuthenticatedAttributes()
    {
        return authenticatedAttributes;
    }

    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digAlgorithm;
    }

    public ASN1OctetString getEncryptedDigest()
    {
        return encryptedDigest;
    }

    public AlgorithmIdentifier getDigestEncryptionAlgorithm()
    {
        return digEncryptionAlgorithm;
    }

    public ASN1Set getUnauthenticatedAttributes()
    {
        return unauthenticatedAttributes;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(sid);
        v.add(digAlgorithm);

        if (authenticatedAttributes != null)
        {
            v.add(new DERTaggedObject(false, 0, authenticatedAttributes));
        }

        v.add(digEncryptionAlgorithm);
        v.add(encryptedDigest);

        if (unauthenticatedAttributes != null)
        {
            v.add(new DERTaggedObject(false, 1, unauthenticatedAttributes));
        }

        return new DERSequence(v);
    }
}
