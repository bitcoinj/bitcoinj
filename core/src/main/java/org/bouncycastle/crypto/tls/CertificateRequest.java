package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * Parsing and encoding of a <i>CertificateRequest</i> struct from RFC 4346.
 * <pre>
 * struct {
 *     ClientCertificateType certificate_types&lt;1..2^8-1&gt;;
 *     DistinguishedName certificate_authorities&lt;3..2^16-1&gt;;
 * } CertificateRequest;
 * </pre>
 *
 * @see ClientCertificateType
 * @see X500Name
 */
public class CertificateRequest
{
    protected short[] certificateTypes;
    protected Vector supportedSignatureAlgorithms;
    protected Vector certificateAuthorities;

    /**
     * @param certificateTypes       see {@link ClientCertificateType} for valid constants.
     * @param certificateAuthorities a {@link Vector} of {@link X500Name}.
     */
    public CertificateRequest(short[] certificateTypes, Vector supportedSignatureAlgorithms, Vector certificateAuthorities)
    {
        this.certificateTypes = certificateTypes;
        this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
        this.certificateAuthorities = certificateAuthorities;
    }

    /**
     * @return an array of certificate types
     * @see ClientCertificateType
     */
    public short[] getCertificateTypes()
    {
        return certificateTypes;
    }

    /**
     * @return a {@link Vector} of {@link SignatureAndHashAlgorithm} (or null before TLS 1.2).
     */
    public Vector getSupportedSignatureAlgorithms()
    {
        return supportedSignatureAlgorithms;
    }

    /**
     * @return a {@link Vector} of {@link X500Name}
     */
    public Vector getCertificateAuthorities()
    {
        return certificateAuthorities;
    }

    /**
     * Encode this {@link CertificateRequest} to an {@link OutputStream}.
     *
     * @param output the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output)
        throws IOException
    {
        if (certificateTypes == null || certificateTypes.length == 0)
        {
            TlsUtils.writeUint8(0, output);
        }
        else
        {
            TlsUtils.writeUint8ArrayWithUint8Length(certificateTypes, output);
        }

        if (supportedSignatureAlgorithms != null)
        {
            // TODO Check whether SignatureAlgorithm.anonymous is allowed here
            TlsUtils.encodeSupportedSignatureAlgorithms(supportedSignatureAlgorithms, false, output);
        }

        if (certificateAuthorities == null || certificateAuthorities.isEmpty())
        {
            TlsUtils.writeUint16(0, output);
        }
        else
        {
            Vector derEncodings = new Vector(certificateAuthorities.size());

            int totalLength = 0;
            for (int i = 0; i < certificateAuthorities.size(); ++i)
            {
                X500Name certificateAuthority = (X500Name)certificateAuthorities.elementAt(i);
                byte[] derEncoding = certificateAuthority.getEncoded(ASN1Encoding.DER);
                derEncodings.addElement(derEncoding);
                totalLength += derEncoding.length;
            }

            TlsUtils.checkUint16(totalLength);
            TlsUtils.writeUint16(totalLength, output);

            for (int i = 0; i < derEncodings.size(); ++i)
            {
                byte[] encDN = (byte[])derEncodings.elementAt(i);
                output.write(encDN);
            }
        }
    }

    /**
     * Parse a {@link CertificateRequest} from an {@link InputStream}.
     * 
     * @param context
     *            the {@link TlsContext} of the current connection.
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link CertificateRequest} object.
     * @throws IOException
     */
    public static CertificateRequest parse(TlsContext context, InputStream input)
        throws IOException
    {
        int numTypes = TlsUtils.readUint8(input);
        short[] certificateTypes = new short[numTypes];
        for (int i = 0; i < numTypes; ++i)
        {
            certificateTypes[i] = TlsUtils.readUint8(input);
        }

        Vector supportedSignatureAlgorithms = null;
        if (TlsUtils.isTLSv12(context))
        {
            // TODO Check whether SignatureAlgorithm.anonymous is allowed here
            supportedSignatureAlgorithms = TlsUtils.parseSupportedSignatureAlgorithms(false, input);
        }

        Vector certificateAuthorities = new Vector();
        byte[] certAuthData = TlsUtils.readOpaque16(input);
        ByteArrayInputStream bis = new ByteArrayInputStream(certAuthData);
        while (bis.available() > 0)
        {
            byte[] derEncoding = TlsUtils.readOpaque16(bis);
            ASN1Primitive asn1 = TlsUtils.readDERObject(derEncoding);
            certificateAuthorities.addElement(X500Name.getInstance(asn1));
        }

        return new CertificateRequest(certificateTypes, supportedSignatureAlgorithms, certificateAuthorities);
    }
}
