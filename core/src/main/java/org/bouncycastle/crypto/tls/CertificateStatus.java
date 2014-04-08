package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ocsp.OCSPResponse;

public class CertificateStatus
{
    protected short statusType;
    protected Object response;

    public CertificateStatus(short statusType, Object response)
    {
        if (!isCorrectType(statusType, response))
        {
            throw new IllegalArgumentException("'response' is not an instance of the correct type");
        }
        
        this.statusType = statusType;
        this.response = response;
    }

    public short getStatusType()
    {
        return statusType;
    }

    public Object getResponse()
    {
        return response;
    }

    public OCSPResponse getOCSPResponse()
    {
        if (!isCorrectType(CertificateStatusType.ocsp, response))
        {
            throw new IllegalStateException("'response' is not an OCSPResponse");
        }
        return (OCSPResponse)response;
    }

    /**
     * Encode this {@link CertificateStatus} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeUint8(statusType, output);

        switch (statusType)
        {
        case CertificateStatusType.ocsp:
            byte[] derEncoding = ((OCSPResponse) response).getEncoded(ASN1Encoding.DER);
            TlsUtils.writeOpaque24(derEncoding, output);
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    /**
     * Parse a {@link CertificateStatus} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link CertificateStatus} object.
     * @throws IOException
     */
    public static CertificateStatus parse(InputStream input) throws IOException
    {
        short status_type = TlsUtils.readUint8(input);
        Object response;

        switch (status_type)
        {
        case CertificateStatusType.ocsp:
        {
            byte[] derEncoding = TlsUtils.readOpaque24(input);
            response = OCSPResponse.getInstance(TlsUtils.readDERObject(derEncoding));
            break;
        }
        default:
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        return new CertificateStatus(status_type, response);
    }

    protected static boolean isCorrectType(short statusType, Object response)
    {
        switch (statusType)
        {
        case CertificateStatusType.ocsp:
            return response instanceof OCSPResponse;
        default:
            throw new IllegalArgumentException("'statusType' is an unsupported value");
        }
    }
}
