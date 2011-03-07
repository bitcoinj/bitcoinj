package com.google.bitcoin.bouncycastle.bcpg;

import com.google.bitcoin.bouncycastle.bcpg.sig.Exportable;
import com.google.bitcoin.bouncycastle.bcpg.sig.IssuerKeyID;
import com.google.bitcoin.bouncycastle.bcpg.sig.KeyExpirationTime;
import com.google.bitcoin.bouncycastle.bcpg.sig.KeyFlags;
import com.google.bitcoin.bouncycastle.bcpg.sig.NotationData;
import com.google.bitcoin.bouncycastle.bcpg.sig.PreferredAlgorithms;
import com.google.bitcoin.bouncycastle.bcpg.sig.PrimaryUserID;
import com.google.bitcoin.bouncycastle.bcpg.sig.Revocable;
import com.google.bitcoin.bouncycastle.bcpg.sig.SignatureCreationTime;
import com.google.bitcoin.bouncycastle.bcpg.sig.SignatureExpirationTime;
import com.google.bitcoin.bouncycastle.bcpg.sig.SignerUserID;
import com.google.bitcoin.bouncycastle.bcpg.sig.TrustSignature;
import com.google.bitcoin.bouncycastle.util.io.Streams;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/**
 * reader for signature sub-packets
 */
public class SignatureSubpacketInputStream
    extends InputStream implements SignatureSubpacketTags
{
    InputStream    in;
    
    public SignatureSubpacketInputStream(
        InputStream    in)
    {
        this.in = in;
    }
    
    public int available()
        throws IOException
    {
        return in.available();
    }
    
    public int read()
        throws IOException
    {
        return in.read();
    }

    public SignatureSubpacket readPacket()
        throws IOException
    {
        int            l = this.read();
        int            bodyLen = 0;
        
        if (l < 0)
        {
            return null;
        }

        if (l < 192)
        {
            bodyLen = l;
        }
        else if (l <= 223)
        {
            bodyLen = ((l - 192) << 8) + (in.read()) + 192;
        }
        else if (l == 255)
        {
            bodyLen = (in.read() << 24) | (in.read() << 16) |  (in.read() << 8)  | in.read();
        }
        else
        {
            // TODO Error?
        }

        int        tag = in.read();

        if (tag < 0)
        {
               throw new EOFException("unexpected EOF reading signature sub packet");
        }
       
        byte[]    data = new byte[bodyLen - 1];
        if (Streams.readFully(in, data) < data.length)
        {
            throw new EOFException();
        }
       
        boolean   isCritical = ((tag & 0x80) != 0);
        int       type = tag & 0x7f;

        switch (type)
        {
        case CREATION_TIME:
            return new SignatureCreationTime(isCritical, data);
        case KEY_EXPIRE_TIME:
            return new KeyExpirationTime(isCritical, data);
        case EXPIRE_TIME:
            return new SignatureExpirationTime(isCritical, data);
        case REVOCABLE:
            return new Revocable(isCritical, data);
        case EXPORTABLE:
            return new Exportable(isCritical, data);
        case ISSUER_KEY_ID:
            return new IssuerKeyID(isCritical, data);
        case TRUST_SIG:
            return new TrustSignature(isCritical, data);
        case PREFERRED_COMP_ALGS:
        case PREFERRED_HASH_ALGS:
        case PREFERRED_SYM_ALGS:
            return new PreferredAlgorithms(type, isCritical, data);
        case KEY_FLAGS:
            return new KeyFlags(isCritical, data);
        case PRIMARY_USER_ID:
            return new PrimaryUserID(isCritical, data);
        case SIGNER_USER_ID:
            return new SignerUserID(isCritical, data);
        case NOTATION_DATA:
            return new NotationData(isCritical, data);
        }

        return new SignatureSubpacket(type, isCritical, data);
    }
}
