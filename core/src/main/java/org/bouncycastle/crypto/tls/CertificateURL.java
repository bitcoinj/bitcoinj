package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

/*
 * RFC 3546 3.3
 */
public class CertificateURL
{
    protected short type;
    protected Vector urlAndHashList;

    /**
     * @param type
     *            see {@link CertChainType} for valid constants.
     * @param urlAndHashList
     *            a {@link Vector} of {@link URLAndHash}.
     */
    public CertificateURL(short type, Vector urlAndHashList)
    {
        if (!CertChainType.isValid(type))
        {
            throw new IllegalArgumentException("'type' is not a valid CertChainType value");
        }
        if (urlAndHashList == null || urlAndHashList.isEmpty())
        {
            throw new IllegalArgumentException("'urlAndHashList' must have length > 0");
        }

        this.type = type;
        this.urlAndHashList = urlAndHashList;
    }

    /**
     * @return {@link CertChainType}
     */
    public short getType()
    {
        return type;
    }

    /**
     * @return a {@link Vector} of {@link URLAndHash} 
     */
    public Vector getURLAndHashList()
    {
        return urlAndHashList;
    }

    /**
     * Encode this {@link CertificateURL} to an {@link OutputStream}.
     *
     * @param output the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output)
        throws IOException
    {
        TlsUtils.writeUint8(this.type, output);

        ListBuffer16 buf = new ListBuffer16();
        for (int i = 0; i < this.urlAndHashList.size(); ++i)
        {
            URLAndHash urlAndHash = (URLAndHash)this.urlAndHashList.elementAt(i);
            urlAndHash.encode(buf);
        }
        buf.encodeTo(output);
    }

    /**
     * Parse a {@link CertificateURL} from an {@link InputStream}.
     * 
     * @param context
     *            the {@link TlsContext} of the current connection.
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link CertificateURL} object.
     * @throws IOException
     */
    public static CertificateURL parse(TlsContext context, InputStream input)
        throws IOException
    {
        short type = TlsUtils.readUint8(input);
        if (!CertChainType.isValid(type))
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        int totalLength = TlsUtils.readUint16(input);
        if (totalLength < 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        byte[] urlAndHashListData = TlsUtils.readFully(totalLength, input);

        ByteArrayInputStream buf = new ByteArrayInputStream(urlAndHashListData);

        Vector url_and_hash_list = new Vector();
        while (buf.available() > 0)
        {
            URLAndHash url_and_hash = URLAndHash.parse(context, buf);
            url_and_hash_list.addElement(url_and_hash);
        }

        return new CertificateURL(type, url_and_hash_list);
    }

    // TODO Could be more generally useful
    class ListBuffer16 extends ByteArrayOutputStream
    {
        ListBuffer16() throws IOException
        {
            // Reserve space for length
            TlsUtils.writeUint16(0,  this);
        }

        void encodeTo(OutputStream output) throws IOException
        {
            // Patch actual length back in
            int length = count - 2;
            TlsUtils.checkUint16(length);
            TlsUtils.writeUint16(length, buf, 0);
            output.write(buf, 0, count);
            buf = null;
        }
    }
}
