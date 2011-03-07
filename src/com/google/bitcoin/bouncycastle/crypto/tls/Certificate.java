package com.google.bitcoin.bouncycastle.crypto.tls;

import com.google.bitcoin.bouncycastle.asn1.ASN1InputStream;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.x509.X509CertificateStructure;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

/**
 * A representation for a certificate chain as used by an tls server.
 */
public class Certificate
{
    /**
     * The certificates.
     */
    protected X509CertificateStructure[] certs;

    /**
     * Parse the ServerCertificate message.
     *
     * @param is The stream where to parse from.
     * @return A Certificate object with the certs, the server has sended.
     * @throws IOException If something goes wrong during parsing.
     */
    protected static Certificate parse(InputStream is) throws IOException
    {
        X509CertificateStructure[] certs;
        int left = TlsUtils.readUint24(is);
        Vector tmp = new Vector();
        while (left > 0)
        {
            int size = TlsUtils.readUint24(is);
            left -= 3 + size;
            byte[] buf = new byte[size];
            TlsUtils.readFully(buf, is);
            ByteArrayInputStream bis = new ByteArrayInputStream(buf);
            ASN1InputStream ais = new ASN1InputStream(bis);
            DERObject o = ais.readObject();
            tmp.addElement(X509CertificateStructure.getInstance(o));
            if (bis.available() > 0)
            {
                throw new IllegalArgumentException("Sorry, there is garbage data left after the certificate");
            }
        }
        certs = new X509CertificateStructure[tmp.size()];
        for (int i = 0; i < tmp.size(); i++)
        {
            certs[i] = (X509CertificateStructure)tmp.elementAt(i);
        }
        return new Certificate(certs);
    }

    /**
     * Private constructure from an cert array.
     *
     * @param certs The certs the chain should contain.
     */
    private Certificate(X509CertificateStructure[] certs)
    {
        this.certs = certs;
    }

    /**
     * @return An array which contains the certs, this chain contains.
     */
    public X509CertificateStructure[] getCerts()
    {
        X509CertificateStructure[] result = new X509CertificateStructure[certs.length];
        System.arraycopy(certs, 0, result, 0, certs.length);
        return result;
    }

}
