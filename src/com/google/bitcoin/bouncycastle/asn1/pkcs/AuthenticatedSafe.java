package com.google.bitcoin.bouncycastle.asn1.pkcs;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.BERSequence;
import com.google.bitcoin.bouncycastle.asn1.DERObject;

public class AuthenticatedSafe
    extends ASN1Encodable
{
    ContentInfo[]    info;

    public AuthenticatedSafe(
        ASN1Sequence  seq)
    {
        info = new ContentInfo[seq.size()];

        for (int i = 0; i != info.length; i++)
        {
            info[i] = ContentInfo.getInstance(seq.getObjectAt(i));
        }
    }

    public AuthenticatedSafe(
        ContentInfo[]       info)
    {
        this.info = info;
    }

    public ContentInfo[] getContentInfo()
    {
        return info;
    }

    public DERObject toASN1Object()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        for (int i = 0; i != info.length; i++)
        {
            v.add(info[i]);
        }

        return new BERSequence(v);
    }
}
