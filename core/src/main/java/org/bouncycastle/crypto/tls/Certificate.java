package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * Parsing and encoding of a <i>Certificate</i> struct from RFC 4346.
 * <pre>
 * opaque ASN.1Cert&lt;2^24-1&gt;;
 *
 * struct {
 *     ASN.1Cert certificate_list&lt;0..2^24-1&gt;;
 * } Certificate;
 * </pre>
 *
 * @see org.bouncycastle.asn1.x509.Certificate
 */
public class Certificate
{
    public static final Certificate EMPTY_CHAIN = new Certificate(
        new org.bouncycastle.asn1.x509.Certificate[0]);

    protected org.bouncycastle.asn1.x509.Certificate[] certificateList;

    public Certificate(org.bouncycastle.asn1.x509.Certificate[] certificateList)
    {
        if (certificateList == null)
        {
            throw new IllegalArgumentException("'certificateList' cannot be null");
        }

        this.certificateList = certificateList;
    }

    /**
     * @deprecated use {@link #getCertificateList()} instead
     */
    public org.bouncycastle.asn1.x509.Certificate[] getCerts()
    {
        return getCertificateList();
    }

    /**
     * @return an array of {@link org.bouncycastle.asn1.x509.Certificate} representing a certificate
     *         chain.
     */
    public org.bouncycastle.asn1.x509.Certificate[] getCertificateList()
    {
        return cloneCertificateList();
    }

    public org.bouncycastle.asn1.x509.Certificate getCertificateAt(int index)
    {
        return certificateList[index];
    }

    public int getLength()
    {
        return certificateList.length;
    }

    /**
     * @return <code>true</code> if this certificate chain contains no certificates, or
     *         <code>false</code> otherwise.
     */
    public boolean isEmpty()
    {
        return certificateList.length == 0;
    }

    /**
     * Encode this {@link Certificate} to an {@link OutputStream}.
     *
     * @param output the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output)
        throws IOException
    {
        Vector derEncodings = new Vector(this.certificateList.length);

        int totalLength = 0;
        for (int i = 0; i < this.certificateList.length; ++i)
        {
            byte[] derEncoding = certificateList[i].getEncoded(ASN1Encoding.DER);
            derEncodings.addElement(derEncoding);
            totalLength += derEncoding.length + 3;
        }

        TlsUtils.checkUint24(totalLength);
        TlsUtils.writeUint24(totalLength, output);

        for (int i = 0; i < derEncodings.size(); ++i)
        {
            byte[] derEncoding = (byte[])derEncodings.elementAt(i);
            TlsUtils.writeOpaque24(derEncoding, output);
        }
    }

    /**
     * Parse a {@link Certificate} from an {@link InputStream}.
     *
     * @param input the {@link InputStream} to parse from.
     * @return a {@link Certificate} object.
     * @throws IOException
     */
    public static Certificate parse(InputStream input)
        throws IOException
    {
        int totalLength = TlsUtils.readUint24(input);
        if (totalLength == 0)
        {
            return EMPTY_CHAIN;
        }

        byte[] certListData = TlsUtils.readFully(totalLength, input);

        ByteArrayInputStream buf = new ByteArrayInputStream(certListData);

        Vector certificate_list = new Vector();
        while (buf.available() > 0)
        {
            byte[] derEncoding = TlsUtils.readOpaque24(buf);
            ASN1Primitive asn1Cert = TlsUtils.readDERObject(derEncoding);
            certificate_list.addElement(org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert));
        }

        org.bouncycastle.asn1.x509.Certificate[] certificateList = new org.bouncycastle.asn1.x509.Certificate[certificate_list.size()];
        for (int i = 0; i < certificate_list.size(); i++)
        {
            certificateList[i] = (org.bouncycastle.asn1.x509.Certificate)certificate_list.elementAt(i);
        }
        return new Certificate(certificateList);
    }

    protected org.bouncycastle.asn1.x509.Certificate[] cloneCertificateList()
    {
        org.bouncycastle.asn1.x509.Certificate[] result = new org.bouncycastle.asn1.x509.Certificate[certificateList.length];
        System.arraycopy(certificateList, 0, result, 0, result.length);
        return result;
    }
}
