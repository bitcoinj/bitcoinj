package org.bouncycastle.asn1.tsp;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extensions;

public class TimeStampReq
    extends ASN1Object
{
    ASN1Integer version;

    MessageImprint messageImprint;

    ASN1ObjectIdentifier tsaPolicy;

    ASN1Integer nonce;

    ASN1Boolean certReq;

    Extensions extensions;

    public static TimeStampReq getInstance(Object o)
    {
        if (o instanceof TimeStampReq)
        {
            return (TimeStampReq) o;
        }
        else if (o != null)
        {
            return new TimeStampReq(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private TimeStampReq(ASN1Sequence seq)
    {
        int nbObjects = seq.size();

        int seqStart = 0;

        // version
        version = ASN1Integer.getInstance(seq.getObjectAt(seqStart));

        seqStart++;

        // messageImprint
        messageImprint = MessageImprint.getInstance(seq.getObjectAt(seqStart));

        seqStart++;

        for (int opt = seqStart; opt < nbObjects; opt++)
        {
            // tsaPolicy
            if (seq.getObjectAt(opt) instanceof ASN1ObjectIdentifier)
            {
                tsaPolicy = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(opt));
            }
            // nonce
            else if (seq.getObjectAt(opt) instanceof ASN1Integer)
            {
                nonce = ASN1Integer.getInstance(seq.getObjectAt(opt));
            }
            // certReq
            else if (seq.getObjectAt(opt) instanceof ASN1Boolean)
            {
                certReq = ASN1Boolean.getInstance(seq.getObjectAt(opt));
            }
            // extensions
            else if (seq.getObjectAt(opt) instanceof ASN1TaggedObject)
            {
                ASN1TaggedObject    tagged = (ASN1TaggedObject)seq.getObjectAt(opt);
                if (tagged.getTagNo() == 0)
                {
                    extensions = Extensions.getInstance(tagged, false);
                }
            }
        }
    }

    public TimeStampReq(
        MessageImprint      messageImprint,
        ASN1ObjectIdentifier tsaPolicy,
        ASN1Integer          nonce,
        ASN1Boolean          certReq,
        Extensions      extensions)
    {
        // default
        version = new ASN1Integer(1);

        this.messageImprint = messageImprint;
        this.tsaPolicy = tsaPolicy;
        this.nonce = nonce;
        this.certReq = certReq;
        this.extensions = extensions;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public MessageImprint getMessageImprint()
    {
        return messageImprint;
    }

    public ASN1ObjectIdentifier getReqPolicy()
    {
        return tsaPolicy;
    }

    public ASN1Integer getNonce()
    {
        return nonce;
    }

    public ASN1Boolean getCertReq()
    {
        return certReq;
    }

    public Extensions getExtensions()
    {
        return extensions;
    }

    /**
     * <pre>
     * TimeStampReq ::= SEQUENCE  {
     *  version                      INTEGER  { v1(1) },
     *  messageImprint               MessageImprint,
     *    --a hash algorithm OID and the hash value of the data to be
     *    --time-stamped
     *  reqPolicy             TSAPolicyId              OPTIONAL,
     *  nonce                 INTEGER                  OPTIONAL,
     *  certReq               BOOLEAN                  DEFAULT FALSE,
     *  extensions            [0] IMPLICIT Extensions  OPTIONAL
     * }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(version);
        v.add(messageImprint);
        
        if (tsaPolicy != null)
        {
            v.add(tsaPolicy);
        }
        
        if (nonce != null)
        {
            v.add(nonce);
        }
        
        if (certReq != null && certReq.isTrue())
        {
            v.add(certReq);
        }
        
        if (extensions != null)
        {
            v.add(new DERTaggedObject(false, 0, extensions));
        }

        return new DERSequence(v);
    }
}
