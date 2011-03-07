package com.google.bitcoin.bouncycastle.asn1.cmp;

import com.google.bitcoin.bouncycastle.asn1.ASN1Choice;
import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERTaggedObject;
import com.google.bitcoin.bouncycastle.asn1.crmf.CertReqMessages;
import com.google.bitcoin.bouncycastle.asn1.pkcs.CertificationRequest;

public class PKIBody
    extends ASN1Encodable
    implements ASN1Choice
{
    private int tagNo;
    private ASN1Encodable body;

    public static PKIBody getInstance(Object o)
    {
        if (o instanceof PKIBody)
        {
            return (PKIBody)o;
        }

        if (o instanceof ASN1TaggedObject)
        {
            return new PKIBody((ASN1TaggedObject)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    private PKIBody(ASN1TaggedObject tagged)
    {
        tagNo = tagged.getTagNo();

        switch (tagged.getTagNo())
        {
        case 0:
            body = CertReqMessages.getInstance(tagged.getObject());
            break;
        case 1:
            body = CertRepMessage.getInstance(tagged.getObject());
            break;
        case 2:
            body = CertReqMessages.getInstance(tagged.getObject());
            break;
        case 3:
            body = CertRepMessage.getInstance(tagged.getObject());
            break;
        case 4:
            body = CertificationRequest.getInstance(tagged.getObject());
            break;
        case 5:
            body = POPODecKeyChallContent.getInstance(tagged.getObject());
            break;
        case 6:
            body = POPODecKeyRespContent.getInstance(tagged.getObject());
            break;
        case 7:
            body = CertReqMessages.getInstance(tagged.getObject());
            break;
        case 8:
            body = CertRepMessage.getInstance(tagged.getObject());
            break;
        case 9:
            body = CertReqMessages.getInstance(tagged.getObject());
            break;
        case 10:
            body = KeyRecRepContent.getInstance(tagged.getObject());
            break;
        case 11:
            body = RevReqContent.getInstance(tagged.getObject());
            break;
        case 12:
            body = RevRepContent.getInstance(tagged.getObject());
            break;
        case 13:
            body = CertReqMessages.getInstance(tagged.getObject());
            break;
        case 14:
            body = CertRepMessage.getInstance(tagged.getObject());
            break;
        case 15:
            body = CAKeyUpdAnnContent.getInstance(tagged.getObject());
            break;
        case 16:
            body = CMPCertificate.getInstance(tagged.getObject());  // CertAnnContent
            break;
        case 17:
            body = RevAnnContent.getInstance(tagged.getObject());
            break;
        case 18:
            body = CRLAnnContent.getInstance(tagged.getObject());
            break;
        case 19:
            body = PKIConfirmContent.getInstance(tagged.getObject());
            break;
        case 20:
            body = PKIMessages.getInstance(tagged.getObject()); // NestedMessageContent
            break;
        case 21:
            body = GenMsgContent.getInstance(tagged.getObject());
            break;
        case 22:
            body = GenRepContent.getInstance(tagged.getObject());
            break;
        case 23:
            body = ErrorMsgContent.getInstance(tagged.getObject());
            break;
        case 24:
            body = CertConfirmContent.getInstance(tagged.getObject());
            break;
        case 25:
            body = PollReqContent.getInstance(tagged.getObject());
            break;
        case 26:
            body = PollRepContent.getInstance(tagged.getObject());
            break;
        default:
            throw new IllegalArgumentException("unknown tag number: " + tagged.getTagNo());
        }
    }

    /**
     * <pre>
     * PKIBody ::= CHOICE {       -- message-specific body elements
     *        ir       [0]  CertReqMessages,        --Initialization Request
     *        ip       [1]  CertRepMessage,         --Initialization Response
     *        cr       [2]  CertReqMessages,        --Certification Request
     *        cp       [3]  CertRepMessage,         --Certification Response
     *        p10cr    [4]  CertificationRequest,   --imported from [PKCS10]
     *        popdecc  [5]  POPODecKeyChallContent, --pop Challenge
     *        popdecr  [6]  POPODecKeyRespContent,  --pop Response
     *        kur      [7]  CertReqMessages,        --Key Update Request
     *        kup      [8]  CertRepMessage,         --Key Update Response
     *        krr      [9]  CertReqMessages,        --Key Recovery Request
     *        krp      [10] KeyRecRepContent,       --Key Recovery Response
     *        rr       [11] RevReqContent,          --Revocation Request
     *        rp       [12] RevRepContent,          --Revocation Response
     *        ccr      [13] CertReqMessages,        --Cross-Cert. Request
     *        ccp      [14] CertRepMessage,         --Cross-Cert. Response
     *        ckuann   [15] CAKeyUpdAnnContent,     --CA Key Update Ann.
     *        cann     [16] CertAnnContent,         --Certificate Ann.
     *        rann     [17] RevAnnContent,          --Revocation Ann.
     *        crlann   [18] CRLAnnContent,          --CRL Announcement
     *        pkiconf  [19] PKIConfirmContent,      --Confirmation
     *        nested   [20] NestedMessageContent,   --Nested Message
     *        genm     [21] GenMsgContent,          --General Message
     *        genp     [22] GenRepContent,          --General Response
     *        error    [23] ErrorMsgContent,        --Error Message
     *        certConf [24] CertConfirmContent,     --Certificate confirm
     *        pollReq  [25] PollReqContent,         --Polling request
     *        pollRep  [26] PollRepContent          --Polling response
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public DERObject toASN1Object()
    {
        return new DERTaggedObject(true, tagNo, body);
    }
}
