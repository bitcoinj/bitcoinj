package org.bouncycastle.asn1.dvcs;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * <pre>
 *     DVCSErrorNotice ::= SEQUENCE {
 *         transactionStatus           PKIStatusInfo ,
 *         transactionIdentifier       GeneralName OPTIONAL
 *     }
 * </pre>
 */
public class DVCSErrorNotice
    extends ASN1Object
{
    private PKIStatusInfo transactionStatus;
    private GeneralName transactionIdentifier;

    public DVCSErrorNotice(PKIStatusInfo status)
    {
        this(status, null);
    }

    public DVCSErrorNotice(PKIStatusInfo status, GeneralName transactionIdentifier)
    {
        this.transactionStatus = status;
        this.transactionIdentifier = transactionIdentifier;
    }

    private DVCSErrorNotice(ASN1Sequence seq)
    {
        this.transactionStatus = PKIStatusInfo.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1)
        {
            this.transactionIdentifier = GeneralName.getInstance(seq.getObjectAt(1));
        }
    }

    public static DVCSErrorNotice getInstance(Object obj)
    {
        if (obj instanceof DVCSErrorNotice)
        {
            return (DVCSErrorNotice)obj;
        }
        else if (obj != null)
        {
            return new DVCSErrorNotice(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static DVCSErrorNotice getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(transactionStatus);
        if (transactionIdentifier != null)
        {
            v.add(transactionIdentifier);
        }
        return new DERSequence(v);
    }

    public String toString()
    {
        return "DVCSErrorNotice {\n" +
            "transactionStatus: " + transactionStatus + "\n" +
            (transactionIdentifier != null ? "transactionIdentifier: " + transactionIdentifier + "\n" : "") +
            "}\n";
    }


    public PKIStatusInfo getTransactionStatus()
    {
        return transactionStatus;
    }

    public GeneralName getTransactionIdentifier()
    {
        return transactionIdentifier;
    }
}
