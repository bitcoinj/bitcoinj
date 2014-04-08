package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class CertificateStatusRequest
{
    protected short statusType;
    protected Object request;

    public CertificateStatusRequest(short statusType, Object request)
    {
        if (!isCorrectType(statusType, request))
        {
            throw new IllegalArgumentException("'request' is not an instance of the correct type");
        }
        
        this.statusType = statusType;
        this.request = request;
    }

    public short getStatusType()
    {
        return statusType;
    }

    public Object getRequest()
    {
        return request;
    }

    public OCSPStatusRequest getOCSPStatusRequest()
    {
        if (!isCorrectType(CertificateStatusType.ocsp, request))
        {
            throw new IllegalStateException("'request' is not an OCSPStatusRequest");
        }
        return (OCSPStatusRequest)request;
    }

    /**
     * Encode this {@link CertificateStatusRequest} to an {@link OutputStream}.
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
            ((OCSPStatusRequest) request).encode(output);
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    /**
     * Parse a {@link CertificateStatusRequest} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link CertificateStatusRequest} object.
     * @throws IOException
     */
    public static CertificateStatusRequest parse(InputStream input) throws IOException
    {
        short status_type = TlsUtils.readUint8(input);
        Object result;

        switch (status_type)
        {
        case CertificateStatusType.ocsp:
            result = OCSPStatusRequest.parse(input);
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        return new CertificateStatusRequest(status_type, result);
    }

    protected static boolean isCorrectType(short statusType, Object request)
    {
        switch (statusType)
        {
        case CertificateStatusType.ocsp:
            return request instanceof OCSPStatusRequest;
        default:
            throw new IllegalArgumentException("'statusType' is an unsupported value");
        }
    }
}
