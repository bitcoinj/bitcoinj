package org.bouncycastle.asn1.dvcs;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * <pre>
 *     DVCSRequest ::= SEQUENCE  {
 *         requestInformation         DVCSRequestInformation,
 *         data                       Data,
 *         transactionIdentifier      GeneralName OPTIONAL
 *     }
 * </pre>
 */

public class DVCSRequest
    extends ASN1Object
{

    private DVCSRequestInformation requestInformation;
    private Data data;
    private GeneralName transactionIdentifier;

    public DVCSRequest(DVCSRequestInformation requestInformation, Data data)
    {
        this(requestInformation, data, null);
    }

    public DVCSRequest(DVCSRequestInformation requestInformation, Data data, GeneralName transactionIdentifier)
    {
        this.requestInformation = requestInformation;
        this.data = data;
        this.transactionIdentifier = transactionIdentifier;
    }

    private DVCSRequest(ASN1Sequence seq)
    {
        requestInformation = DVCSRequestInformation.getInstance(seq.getObjectAt(0));
        data = Data.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2)
        {
            transactionIdentifier = GeneralName.getInstance(seq.getObjectAt(2));
        }
    }

    public static DVCSRequest getInstance(Object obj)
    {
        if (obj instanceof DVCSRequest)
        {
            return (DVCSRequest)obj;
        }
        else if (obj != null)
        {
            return new DVCSRequest(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static DVCSRequest getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(requestInformation);
        v.add(data);
        if (transactionIdentifier != null)
        {
            v.add(transactionIdentifier);
        }
        return new DERSequence(v);
    }

    public String toString()
    {
        return "DVCSRequest {\n" +
            "requestInformation: " + requestInformation + "\n" +
            "data: " + data + "\n" +
            (transactionIdentifier != null ? "transactionIdentifier: " + transactionIdentifier + "\n" : "") +
            "}\n";
    }

    public Data getData()
    {
        return data;
    }

    public DVCSRequestInformation getRequestInformation()
    {
        return requestInformation;
    }

    public GeneralName getTransactionIdentifier()
    {
        return transactionIdentifier;
    }
}
