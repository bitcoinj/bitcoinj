package org.bouncycastle.util.io.pem;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;

public class PemReader
    extends BufferedReader
{
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";

    public PemReader(Reader reader)
    {
        super(reader);
    }

    public PemObject readPemObject()
        throws IOException
    {
        String line = readLine();

        while (line != null && !line.startsWith(BEGIN))
        {
            line = readLine();
        }

        if (line != null)
        {
            line = line.substring(BEGIN.length());
            int index = line.indexOf('-');
            String type = line.substring(0, index);

            if (index > 0)
            {
                return loadObject(type);
            }
        }

        return null;
    }

    private PemObject loadObject(String type)
        throws IOException
    {
        String          line;
        String          endMarker = END + type;
        StringBuffer    buf = new StringBuffer();
        List            headers = new ArrayList();

        while ((line = readLine()) != null)
        {
            if (line.indexOf(":") >= 0)
            {
                int index = line.indexOf(':');
                String hdr = line.substring(0, index);
                String value = line.substring(index + 1).trim();

                headers.add(new PemHeader(hdr, value));

                continue;
            }

            if (line.indexOf(endMarker) != -1)
            {
                break;
            }
            
            buf.append(line.trim());
        }

        if (line == null)
        {
            throw new IOException(endMarker + " not found");
        }

        return new PemObject(type, headers, Base64.decode(buf.toString()));
    }

}
