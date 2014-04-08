package org.bouncycastle.bcpg;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.Revocable;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

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

        //
        // this may seem a bit strange but it turns out some applications miscode the length
        // in fixed length fields, so we check the length we do get, only throwing an exception if
        // we really cannot continue
        //
        int bytesRead = Streams.readFully(in, data);

        boolean   isCritical = ((tag & 0x80) != 0);
        int       type = tag & 0x7f;

        if (bytesRead != data.length)
        {
            switch (type)
            {
            case CREATION_TIME:
                data = checkData(data, 4, bytesRead, "Signature Creation Time");
                break;
            case ISSUER_KEY_ID:
                data = checkData(data, 8, bytesRead, "Issuer");
                break;
            case KEY_EXPIRE_TIME:
                data = checkData(data, 4, bytesRead, "Signature Key Expiration Time");
                break;
            case EXPIRE_TIME:
                data = checkData(data, 4, bytesRead, "Signature Expiration Time");
                break;
            default:
                throw new EOFException("truncated subpacket data.");
            }
        }

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

    private byte[] checkData(byte[] data, int expected, int bytesRead, String name)
        throws EOFException
    {
        if (bytesRead != expected)
        {
            throw new EOFException("truncated " + name + " subpacket data.");
        }

        return Arrays.copyOfRange(data, 0, expected);
    }
}
