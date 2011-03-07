package com.google.bitcoin.bouncycastle.bcpg;

import com.google.bitcoin.bouncycastle.util.io.Streams;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/**
 * reader for PGP objects
 */
public class BCPGInputStream
    extends InputStream implements PacketTags
{
    InputStream    in;
    boolean        next = false;
    int            nextB;
    
    public BCPGInputStream(
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
        if (next)
        {
            next = false;

            return nextB;
        }
        else
        {
            return in.read();
        }
    }

    public int read(
        byte[] buf,
        int off,
        int len)
        throws IOException
    {
        if (len == 0)
        {
            return 0;
        }

        if (!next)
        {
            return in.read(buf, off, len);
        }

        // We have next byte waiting, so return it

        if (nextB < 0)
        {
            return -1; // EOF
        }

        buf[off] = (byte)nextB;  // May throw NullPointerException...
        next = false;            // ...so only set this afterwards

        return 1;
    }

    public void readFully(
        byte[]    buf,
        int       off,
        int       len)
        throws IOException
    {
        if (Streams.readFully(this, buf, off, len) < len)
        {
            throw new EOFException();
        }
    }
    
    public void readFully(
        byte[]    buf)
        throws IOException
    {
        readFully(buf, 0, buf.length);
    }

    /**
     * returns the next packet tag in the stream.
     * 
     * @return the tag number.
     * 
     * @throws IOException
     */
    public int nextPacketTag()
        throws IOException
    {
        if (!next)
        {
            try
            {
                nextB = in.read();
            }
            catch (EOFException e)
            {
                nextB = -1;
            }
        } 
        
        next = true;

        if (nextB >= 0)
        {
            if ((nextB & 0x40) != 0)    // new
            {
                return (nextB & 0x3f);
            }
            else    // old
            {
                return ((nextB & 0x3f) >> 2);
            }
        }
        
        return nextB;
    }

    public Packet readPacket()
        throws IOException
    {
        int    hdr = this.read();
        
        if (hdr < 0)
        {
            return null;
        }
        
        if ((hdr & 0x80) == 0)
        {
            throw new IOException("invalid header encountered");
        }

        boolean    newPacket = (hdr & 0x40) != 0;
        int        tag = 0;
        int        bodyLen = 0;
        boolean    partial = false;
        
        if (newPacket)
        {
            tag = hdr & 0x3f;
            
            int    l = this.read();

            if (l < 192)
            {
                bodyLen = l;
            }
            else if (l <= 223)
            {
                int b = in.read();

                bodyLen = ((l - 192) << 8) + (b) + 192;
            }
            else if (l == 255)
            {
                bodyLen = (in.read() << 24) | (in.read() << 16) |  (in.read() << 8)  | in.read();
            }
            else
            {
                partial = true;
                bodyLen = 1 << (l & 0x1f);
            }
        }
        else
        {
            int lengthType = hdr & 0x3;
            
            tag = (hdr & 0x3f) >> 2;

            switch (lengthType)
            {
            case 0:
                bodyLen = this.read();
                break;
            case 1:
                bodyLen = (this.read() << 8) | this.read();
                break;
            case 2:
                bodyLen = (this.read() << 24) | (this.read() << 16) | (this.read() << 8) | this.read();
                break;
            case 3:
                partial = true;
                break;
            default:
                throw new IOException("unknown length type encountered");
            }
        }

        BCPGInputStream    objStream;
        
        if (bodyLen == 0 && partial)
        {
            objStream = this;
        }
        else
        {
            objStream = new BCPGInputStream(new PartialInputStream(this, partial, bodyLen));
        }

        switch (tag)
        {
        case RESERVED:
            return new InputStreamPacket(objStream);
        case PUBLIC_KEY_ENC_SESSION:
            return new PublicKeyEncSessionPacket(objStream);
        case SIGNATURE:
            return new SignaturePacket(objStream);
        case SYMMETRIC_KEY_ENC_SESSION:
            return new SymmetricKeyEncSessionPacket(objStream);
        case ONE_PASS_SIGNATURE:
            return new OnePassSignaturePacket(objStream);
        case SECRET_KEY:
            return new SecretKeyPacket(objStream);
        case PUBLIC_KEY:
            return new PublicKeyPacket(objStream);
        case SECRET_SUBKEY:
            return new SecretSubkeyPacket(objStream);
        case COMPRESSED_DATA:
            return new CompressedDataPacket(objStream);
        case SYMMETRIC_KEY_ENC:
            return new SymmetricEncDataPacket(objStream);
        case MARKER:
            return new MarkerPacket(objStream);
        case LITERAL_DATA:
            return new LiteralDataPacket(objStream);
        case TRUST:
            return new TrustPacket(objStream);
        case USER_ID:
            return new UserIDPacket(objStream);
        case USER_ATTRIBUTE:
            return new UserAttributePacket(objStream);
        case PUBLIC_SUBKEY:
            return new PublicSubkeyPacket(objStream);
        case SYM_ENC_INTEGRITY_PRO:
            return new SymmetricEncIntegrityPacket(objStream);
        case MOD_DETECTION_CODE:
            return new ModDetectionCodePacket(objStream);
        case EXPERIMENTAL_1:
        case EXPERIMENTAL_2:
        case EXPERIMENTAL_3:
        case EXPERIMENTAL_4:
            return new ExperimentalPacket(tag, objStream);
        default:
            throw new IOException("unknown packet type encountered: " + tag);
        }
    }
    
    public void close()
        throws IOException
    {
        in.close();
    }
    
    /**
     * a stream that overlays our input stream, allowing the user to only read a segment of it.
     *
     * NB: dataLength will be negative if the segment length is in the upper range above 2**31.
     */
    private static class PartialInputStream
        extends InputStream
    {
        private BCPGInputStream     in;
        private boolean             partial;
        private int                 dataLength;

        PartialInputStream(
            BCPGInputStream  in,
            boolean          partial,
            int              dataLength)
        {
            this.in = in;
            this.partial = partial;
            this.dataLength = dataLength;
        }

        public int available()
            throws IOException
        {
            int avail = in.available();

            if (avail <= dataLength || dataLength < 0)
            {
                return avail;
            }
            else
            {
                if (partial && dataLength == 0)
                {
                    return 1;
                }
                return dataLength;
            }
        }

        private int loadDataLength()
            throws IOException
        {
            int            l = in.read();
            
            if (l < 0)
            {
                return -1;
            }
            
            partial = false;
            if (l < 192)
            {
                dataLength = l;
            }
            else if (l <= 223)
            {
                dataLength = ((l - 192) << 8) + (in.read()) + 192;
            }
            else if (l == 255)
            {
                dataLength = (in.read() << 24) | (in.read() << 16) |  (in.read() << 8)  | in.read();
            }
            else
            {
                partial = true;
                dataLength = 1 << (l & 0x1f);
            }
            
            return dataLength;
        }
        
        public int read(byte[] buf, int offset, int len)
            throws IOException
        {
            do
            {
                if (dataLength != 0)
                {
                    int readLen = (dataLength > len || dataLength < 0) ? len : dataLength;
                    readLen = in.read(buf, offset, readLen);
                    if (readLen < 0)
                    {
                        throw new EOFException("premature end of stream in PartialInputStream");
                    }
                    dataLength -= readLen;
                    return readLen;
                }
            }
            while (partial && loadDataLength() >= 0);

            return -1;
        }
        
        public int read()
            throws IOException
        {
            do
            {
                if (dataLength != 0)
                {
                    int ch = in.read();
                    if (ch < 0)
                    {
                        throw new EOFException("premature end of stream in PartialInputStream");
                    }
                    dataLength--;
                    return ch;
                }
            }
            while (partial && loadDataLength() >= 0);

            return -1;
        }
    }
}
