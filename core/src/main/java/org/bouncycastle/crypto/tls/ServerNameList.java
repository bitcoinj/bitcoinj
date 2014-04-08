package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

public class ServerNameList
{
    protected Vector serverNameList;

    /**
     * @param serverNameList a {@link Vector} of {@link ServerName}.
     */
    public ServerNameList(Vector serverNameList)
    {
        if (serverNameList == null || serverNameList.isEmpty())
        {
            throw new IllegalArgumentException("'serverNameList' must not be null or empty");
        }

        this.serverNameList = serverNameList;
    }

    /**
     * @return a {@link Vector} of {@link ServerName}.
     */
    public Vector getServerNameList()
    {
        return serverNameList;
    }

    /**
     * Encode this {@link ServerNameList} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        for (int i = 0; i < serverNameList.size(); ++i)
        {
            ServerName entry = (ServerName)serverNameList.elementAt(i);
            entry.encode(buf);
        }

        TlsUtils.checkUint16(buf.size());
        TlsUtils.writeUint16(buf.size(), output);
        buf.writeTo(output);
    }

    /**
     * Parse a {@link ServerNameList} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link ServerNameList} object.
     * @throws IOException
     */
    public static ServerNameList parse(InputStream input) throws IOException
    {
        int length = TlsUtils.readUint16(input);
        if (length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        byte[] data = TlsUtils.readFully(length, input);

        ByteArrayInputStream buf = new ByteArrayInputStream(data);

        Vector server_name_list = new Vector();
        while (buf.available() > 0)
        {
            ServerName entry = ServerName.parse(buf);
            server_name_list.addElement(entry);
        }

        return new ServerNameList(server_name_list);
    }
}
