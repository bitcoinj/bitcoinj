package com.google.bitcoin.bouncycastle.bcpg;

import java.io.*;
import java.util.Enumeration;
import java.util.Hashtable;

/**
 * Basic output stream.
 */
public class ArmoredOutputStream
    extends OutputStream
{
    private static final byte[] encodingTable =
        {
            (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G',
            (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N',
            (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U',
            (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z',
            (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
            (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
            (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
            (byte)'v',
            (byte)'w', (byte)'x', (byte)'y', (byte)'z',
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6',
            (byte)'7', (byte)'8', (byte)'9',
            (byte)'+', (byte)'/'
        };

    /**
     * encode the input data producing a base 64 encoded byte array.
     */
    private void encode(
        OutputStream    out,
        int[]           data,
        int             len)
        throws IOException
    {
        int    d1, d2, d3;

        switch (len)
        {
        case 0:        /* nothing left to do */
            break;
        case 1:
            d1 = data[0];

            out.write(encodingTable[(d1 >>> 2) & 0x3f]);
            out.write(encodingTable[(d1 << 4) & 0x3f]);
            out.write('=');
            out.write('=');
            break;
        case 2:
            d1 = data[0];
            d2 = data[1];

            out.write(encodingTable[(d1 >>> 2) & 0x3f]);
            out.write(encodingTable[((d1 << 4) | (d2 >>> 4)) & 0x3f]);
            out.write(encodingTable[(d2 << 2) & 0x3f]);
            out.write('=');
            break;
        case 3:
            d1 = data[0];
            d2 = data[1];
            d3 = data[2];

            out.write(encodingTable[(d1 >>> 2) & 0x3f]);
            out.write(encodingTable[((d1 << 4) | (d2 >>> 4)) & 0x3f]);
            out.write(encodingTable[((d2 << 2) | (d3 >>> 6)) & 0x3f]);
            out.write(encodingTable[d3 & 0x3f]);
            break;
        default:
            throw new IOException("unknown length in encode");
        }
    }

    OutputStream    out;
    int[]           buf = new int[3];
    int             bufPtr = 0;
    CRC24           crc = new CRC24();
    int             chunkCount = 0;
    int             lastb;

    boolean         start = true;
    boolean         clearText = false;
    boolean         newLine = false;
    
    String          nl = System.getProperty("line.separator");

    String          type;
    String          headerStart = "-----BEGIN PGP ";
    String          headerTail = "-----";
    String          footerStart = "-----END PGP ";
    String          footerTail = "-----";

    String          version = "BCPG v@RELEASE_NAME@";
    
    Hashtable       headers = new Hashtable();
    
    public ArmoredOutputStream(
        OutputStream    out)
    {
        this.out = out;
        
        if (nl == null)
        {
            nl = "\r\n";
        }
        
        resetHeaders();
    }
    
    public ArmoredOutputStream(
        OutputStream    out,
        Hashtable       headers)
    {
        this(out);

        Enumeration e = headers.keys();
        
        while (e.hasMoreElements())
        {
            Object key = e.nextElement();
            
            this.headers.put(key, headers.get(key));
        }
    }
    
    /**
     * Set an additional header entry.
     * 
     * @param name the name of the header entry.
     * @param value the value of the header entry.
     */
    public void setHeader(
        String name,
        String value)
    {
        this.headers.put(name, value);
    }
    
    /**
     * Reset the headers to only contain a Version string.
     */
    public void resetHeaders()
    {
        headers.clear();
        headers.put("Version", version);
    }
    
    /**
     * Start a clear text signed message.
     * @param hashAlgorithm
     */
    public void beginClearText(
        int    hashAlgorithm) 
        throws IOException
    {
        String    hash;
        
        switch (hashAlgorithm)
        {
        case HashAlgorithmTags.SHA1:
            hash = "SHA1";
            break;
        case HashAlgorithmTags.SHA256:
            hash = "SHA256";
            break;
        case HashAlgorithmTags.SHA384:
            hash = "SHA384";
            break;
        case HashAlgorithmTags.SHA512:
            hash = "SHA512";
            break;
        case HashAlgorithmTags.MD2:
            hash = "MD2";
            break;
        case HashAlgorithmTags.MD5:
            hash = "MD5";
            break;
        case HashAlgorithmTags.RIPEMD160:
            hash = "RIPEMD160";
            break;
        default:
            throw new IOException("unknown hash algorithm tag in beginClearText: " + hashAlgorithm);
        }
        
        String armorHdr = "-----BEGIN PGP SIGNED MESSAGE-----" + nl;
        String hdrs = "Hash: " + hash + nl + nl;
        
        for (int i = 0; i != armorHdr.length(); i++)
        {
            out.write(armorHdr.charAt(i));
        }
        
        for (int i = 0; i != hdrs.length(); i++)
        {
            out.write(hdrs.charAt(i));
        }
        
        clearText = true;
        newLine = true;
        lastb = 0;
    }
    
    public void endClearText()
    {
        clearText = false;
    }
    
    private void writeHeaderEntry(
        String name,
        String value) 
        throws IOException
    {
        for (int i = 0; i != name.length(); i++)
        {
            out.write(name.charAt(i));
        }
        
        out.write(':');
        out.write(' ');
        
        for (int i = 0; i != value.length(); i++)
        {
            out.write(value.charAt(i));
        }

        for (int i = 0; i != nl.length(); i++)
        {
            out.write(nl.charAt(i));
        }
    }
    
    public void write(
        int    b)
        throws IOException
    {
        if (clearText)
        {
            out.write(b);

            if (newLine)
            {
                if (!(b == '\n' && lastb == '\r'))
                {
                    newLine = false;
                }
                if (b == '-')
                {
                    out.write(' ');
                    out.write('-');      // dash escape
                }
            }
            if (b == '\r' || (b == '\n' && lastb != '\r'))
            {
                newLine = true;
            }
            lastb = b;
            return;
        }
        
        if (start)
        {
            boolean     newPacket = (b & 0x40) != 0;
            int         tag = 0;
            
            if (newPacket)
            {
                tag = b & 0x3f;
            }
            else
            {
                tag = (b & 0x3f) >> 2;
            }

            switch (tag)
            {
            case PacketTags.PUBLIC_KEY:
                type = "PUBLIC KEY BLOCK";
                break;
            case PacketTags.SECRET_KEY:
                type = "PRIVATE KEY BLOCK";
                break;
            case PacketTags.SIGNATURE:
                type = "SIGNATURE";
                break;
            default:
                type = "MESSAGE";
            }
            
            for (int i = 0; i != headerStart.length(); i++)
            {
                out.write(headerStart.charAt(i));
            }

            for (int i = 0; i != type.length(); i++)
            {
                out.write(type.charAt(i));
            }

            for (int i = 0; i != headerTail.length(); i++)
            {
                out.write(headerTail.charAt(i));
            }

            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charAt(i));
            }
          
            writeHeaderEntry("Version", (String)headers.get("Version"));

            Enumeration e = headers.keys();
            while (e.hasMoreElements())
            {
                String  key = (String)e.nextElement();
                
                if (!key.equals("Version"))
                {
                    writeHeaderEntry(key, (String)headers.get(key));
                }
            }
            
            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charAt(i));
            }

            start = false;
        }

        if (bufPtr == 3)
        {
            encode(out, buf, bufPtr);
            bufPtr = 0;
            if ((++chunkCount & 0xf) == 0)
            {
                for (int i = 0; i != nl.length(); i++)
                {
                    out.write(nl.charAt(i));
                }
            }
        }

        crc.update(b);
        buf[bufPtr++] = b & 0xff;
    }
    
    public void flush()
        throws IOException
    {
    }
    
    /**
     * <b>Note</b>: close does nor close the underlying stream. So it is possible to write
     * multiple objects using armoring to a single stream.
     */
    public void close()
        throws IOException
    {
        if (type != null)
        {
            encode(out, buf, bufPtr);
        
            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charAt(i));
            }
            out.write('=');
        
            int        crcV = crc.getValue();
        
            buf[0] = ((crcV >> 16) & 0xff);
            buf[1] = ((crcV >> 8) & 0xff);
            buf[2] = (crcV & 0xff);
        
            encode(out, buf, 3);
        
            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charAt(i));
            }
        
            for (int i = 0; i != footerStart.length(); i++)
            {
                out.write(footerStart.charAt(i));
            }
        
            for (int i = 0; i != type.length(); i++)
            {
                out.write(type.charAt(i));
            }
        
            for (int i = 0; i != footerTail.length(); i++)
            {
                out.write(footerTail.charAt(i));
            }
        
            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charAt(i));
            }
        
            out.flush();
            
            type = null;
            start = true;
        }
    }
}
