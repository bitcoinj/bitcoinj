package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * Example InfoTypeAndValue contents include, but are not limited
 * to, the following (un-comment in this ASN.1 module and use as
 * appropriate for a given environment):
 * <pre>
 *   id-it-caProtEncCert    OBJECT IDENTIFIER ::= {id-it 1}
 *      CAProtEncCertValue      ::= CMPCertificate
 *   id-it-signKeyPairTypes OBJECT IDENTIFIER ::= {id-it 2}
 *     SignKeyPairTypesValue   ::= SEQUENCE OF AlgorithmIdentifier
 *   id-it-encKeyPairTypes  OBJECT IDENTIFIER ::= {id-it 3}
 *     EncKeyPairTypesValue    ::= SEQUENCE OF AlgorithmIdentifier
 *   id-it-preferredSymmAlg OBJECT IDENTIFIER ::= {id-it 4}
 *      PreferredSymmAlgValue   ::= AlgorithmIdentifier
 *   id-it-caKeyUpdateInfo  OBJECT IDENTIFIER ::= {id-it 5}
 *      CAKeyUpdateInfoValue    ::= CAKeyUpdAnnContent
 *   id-it-currentCRL       OBJECT IDENTIFIER ::= {id-it 6}
 *      CurrentCRLValue         ::= CertificateList
 *   id-it-unsupportedOIDs  OBJECT IDENTIFIER ::= {id-it 7}
 *      UnsupportedOIDsValue    ::= SEQUENCE OF OBJECT IDENTIFIER
 *   id-it-keyPairParamReq  OBJECT IDENTIFIER ::= {id-it 10}
 *      KeyPairParamReqValue    ::= OBJECT IDENTIFIER
 *   id-it-keyPairParamRep  OBJECT IDENTIFIER ::= {id-it 11}
 *      KeyPairParamRepValue    ::= AlgorithmIdentifer
 *   id-it-revPassphrase    OBJECT IDENTIFIER ::= {id-it 12}
 *      RevPassphraseValue      ::= EncryptedValue
 *   id-it-implicitConfirm  OBJECT IDENTIFIER ::= {id-it 13}
 *      ImplicitConfirmValue    ::= NULL
 *   id-it-confirmWaitTime  OBJECT IDENTIFIER ::= {id-it 14}
 *      ConfirmWaitTimeValue    ::= GeneralizedTime
 *   id-it-origPKIMessage   OBJECT IDENTIFIER ::= {id-it 15}
 *      OrigPKIMessageValue     ::= PKIMessages
 *   id-it-suppLangTags     OBJECT IDENTIFIER ::= {id-it 16}
 *      SuppLangTagsValue       ::= SEQUENCE OF UTF8String
 *
 * where
 *
 *   id-pkix OBJECT IDENTIFIER ::= {
 *      iso(1) identified-organization(3)
 *      dod(6) internet(1) security(5) mechanisms(5) pkix(7)}
 * and
 *      id-it   OBJECT IDENTIFIER ::= {id-pkix 4}
 * </pre>
 */
public class InfoTypeAndValue
    extends ASN1Object
{
    private ASN1ObjectIdentifier infoType;
    private ASN1Encodable       infoValue;

    private InfoTypeAndValue(ASN1Sequence seq)
    {
        infoType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

        if (seq.size() > 1)
        {
            infoValue = (ASN1Encodable)seq.getObjectAt(1);
        }
    }

    public static InfoTypeAndValue getInstance(Object o)
    {
        if (o instanceof InfoTypeAndValue)
        {
            return (InfoTypeAndValue)o;
        }

        if (o != null)
        {
            return new InfoTypeAndValue(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public InfoTypeAndValue(
        ASN1ObjectIdentifier infoType)
    {
        this.infoType = infoType;
        this.infoValue = null;
    }

    public InfoTypeAndValue(
        ASN1ObjectIdentifier infoType,
        ASN1Encodable optionalValue)
    {
        this.infoType = infoType;
        this.infoValue = optionalValue;
    }

    public ASN1ObjectIdentifier getInfoType()
    {
        return infoType;
    }

    public ASN1Encodable getInfoValue()
    {
        return infoValue;
    }

    /**
     * <pre>
     * InfoTypeAndValue ::= SEQUENCE {
     *                         infoType               OBJECT IDENTIFIER,
     *                         infoValue              ANY DEFINED BY infoType  OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(infoType);

        if (infoValue != null)
        {
            v.add(infoValue);
        }

        return new DERSequence(v);
    }
}
