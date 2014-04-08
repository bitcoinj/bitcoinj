package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <a href="http://tools.ietf.org/html/rfc5083">RFC 5083</a>:
 *
 * CMS AuthEnveloped Data object.
 * <p>
 * ASN.1:
 * <pre>
 * id-ct-authEnvelopedData OBJECT IDENTIFIER ::= { iso(1)
 *       member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
 *       smime(16) ct(1) 23 }
 *
 * AuthEnvelopedData ::= SEQUENCE {
 *       version CMSVersion,
 *       originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *       recipientInfos RecipientInfos,
 *       authEncryptedContentInfo EncryptedContentInfo,
 *       authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
 *       mac MessageAuthenticationCode,
 *       unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
 * </pre>
 */
public class AuthEnvelopedData
    extends ASN1Object
{
    private ASN1Integer version;
    private OriginatorInfo originatorInfo;
    private ASN1Set recipientInfos;
    private EncryptedContentInfo authEncryptedContentInfo;
    private ASN1Set authAttrs;
    private ASN1OctetString mac;
    private ASN1Set unauthAttrs;

    public AuthEnvelopedData(
        OriginatorInfo originatorInfo,
        ASN1Set recipientInfos,
        EncryptedContentInfo authEncryptedContentInfo,
        ASN1Set authAttrs,
        ASN1OctetString mac,
        ASN1Set unauthAttrs)
    {
        // "It MUST be set to 0."
        this.version = new ASN1Integer(0);

        this.originatorInfo = originatorInfo;

        // TODO
        // "There MUST be at least one element in the collection."
        this.recipientInfos = recipientInfos;

        this.authEncryptedContentInfo = authEncryptedContentInfo;

        // TODO
        // "The authAttrs MUST be present if the content type carried in
        // EncryptedContentInfo is not id-data."
        this.authAttrs = authAttrs;

        this.mac = mac;

        this.unauthAttrs = unauthAttrs;
    }

    /**
     * Constructs AuthEnvelopedData by parsing supplied ASN1Sequence
     * <p>
     * @param seq An ASN1Sequence with AuthEnvelopedData
     * @deprecated use getInstance().
     */
    public AuthEnvelopedData(
        ASN1Sequence seq)
    {
        int index = 0;

        // TODO
        // "It MUST be set to 0."
        ASN1Primitive tmp = seq.getObjectAt(index++).toASN1Primitive();
        version = (ASN1Integer)tmp;

        tmp = seq.getObjectAt(index++).toASN1Primitive();
        if (tmp instanceof ASN1TaggedObject)
        {
            originatorInfo = OriginatorInfo.getInstance((ASN1TaggedObject)tmp, false);
            tmp = seq.getObjectAt(index++).toASN1Primitive();
        }

        // TODO
        // "There MUST be at least one element in the collection."
        recipientInfos = ASN1Set.getInstance(tmp);

        tmp = seq.getObjectAt(index++).toASN1Primitive();
        authEncryptedContentInfo = EncryptedContentInfo.getInstance(tmp);

        tmp = seq.getObjectAt(index++).toASN1Primitive();
        if (tmp instanceof ASN1TaggedObject)
        {
            authAttrs = ASN1Set.getInstance((ASN1TaggedObject)tmp, false);
            tmp = seq.getObjectAt(index++).toASN1Primitive();
        }
        else
        {
            // TODO
            // "The authAttrs MUST be present if the content type carried in
            // EncryptedContentInfo is not id-data."
        }

        mac = ASN1OctetString.getInstance(tmp);

        if (seq.size() > index)
        {
            tmp = seq.getObjectAt(index++).toASN1Primitive();
            unauthAttrs = ASN1Set.getInstance((ASN1TaggedObject)tmp, false);
        }
    }

    /**
     * Return an AuthEnvelopedData object from a tagged object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats
     * </ul>
     *

     * @param obj      the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws IllegalArgumentException if the object held by the
     *                                  tagged object cannot be converted.
     */
    public static AuthEnvelopedData getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Return an AuthEnvelopedData object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link AuthEnvelopedData} object
     * <li> {@link ASN1Sequence org.bouncycastle.asn1.ASN1Sequence} input formats with AuthEnvelopedData structure inside
     * </ul>
     *
     * @param obj The object we want converted.
     * @throws IllegalArgumentException if the object cannot be converted, or was null.
     */
    public static AuthEnvelopedData getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof AuthEnvelopedData)
        {
            return (AuthEnvelopedData)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new AuthEnvelopedData((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("Invalid AuthEnvelopedData: " + obj.getClass().getName());
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public OriginatorInfo getOriginatorInfo()
    {
        return originatorInfo;
    }

    public ASN1Set getRecipientInfos()
    {
        return recipientInfos;
    }

    public EncryptedContentInfo getAuthEncryptedContentInfo()
    {
        return authEncryptedContentInfo;
    }

    public ASN1Set getAuthAttrs()
    {
        return authAttrs;
    }

    public ASN1OctetString getMac()
    {
        return mac;
    }

    public ASN1Set getUnauthAttrs()
    {
        return unauthAttrs;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);

        if (originatorInfo != null)
        {
            v.add(new DERTaggedObject(false, 0, originatorInfo));
        }

        v.add(recipientInfos);
        v.add(authEncryptedContentInfo);

        // "authAttrs optionally contains the authenticated attributes."
        if (authAttrs != null)
        {
            // "AuthAttributes MUST be DER encoded, even if the rest of the
            // AuthEnvelopedData structure is BER encoded."
            v.add(new DERTaggedObject(false, 1, authAttrs));
        }

        v.add(mac);

        // "unauthAttrs optionally contains the unauthenticated attributes."
        if (unauthAttrs != null)
        {
            v.add(new DERTaggedObject(false, 2, unauthAttrs));
        }

        return new BERSequence(v);
    }
}
