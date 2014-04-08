package org.bouncycastle.asn1.dvcs;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.DigestInfo;

/**
 * <pre>
 * Data ::= CHOICE {
 *   message           OCTET STRING ,
 *   messageImprint    DigestInfo,
 *   certs             [0] SEQUENCE SIZE (1..MAX) OF
 *                         TargetEtcChain
 * }
 * </pre>
 */

public class Data
    extends ASN1Object
    implements ASN1Choice
{
    private ASN1OctetString message;
    private DigestInfo messageImprint;
    private ASN1Sequence certs;

    public Data(byte[] messageBytes)
    {
        this.message = new DEROctetString(messageBytes);
    }

    public Data(ASN1OctetString message)
    {
        this.message = message;
    }

    public Data(DigestInfo messageImprint)
    {
        this.messageImprint = messageImprint;
    }

    public Data(TargetEtcChain cert)
    {
        this.certs = new DERSequence(cert);
    }

    public Data(TargetEtcChain[] certs)
    {
        this.certs = new DERSequence(certs);
    }

    private Data(ASN1Sequence certs)
    {
        this.certs = certs;
    }

    public static Data getInstance(Object obj)
    {
        if (obj instanceof Data)
        {
            return (Data)obj;
        }
        else if (obj instanceof ASN1OctetString)
        {
            return new Data((ASN1OctetString)obj);
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new Data(DigestInfo.getInstance(obj));
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            return new Data(ASN1Sequence.getInstance((ASN1TaggedObject)obj, false));
        }
        throw new IllegalArgumentException("Unknown object submitted to getInstance: " + obj.getClass().getName());
    }

    public static Data getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(obj.getObject());
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (message != null)
        {
            return message.toASN1Primitive();
        }
        if (messageImprint != null)
        {
            return messageImprint.toASN1Primitive();
        }
        else
        {
            return new DERTaggedObject(false, 0, certs);
        }
    }

    public String toString()
    {
        if (message != null)
        {
            return "Data {\n" + message + "}\n";
        }
        if (messageImprint != null)
        {
            return "Data {\n" + messageImprint + "}\n";
        }
        else
        {
            return "Data {\n" + certs + "}\n";
        }
    }

    public ASN1OctetString getMessage()
    {
        return message;
    }

    public DigestInfo getMessageImprint()
    {
        return messageImprint;
    }

    public TargetEtcChain[] getCerts()
    {
        if (certs == null)
        {
            return null;
        }

        TargetEtcChain[] tmp = new TargetEtcChain[certs.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = TargetEtcChain.getInstance(certs.getObjectAt(i));
        }

        return tmp;
    }
}
