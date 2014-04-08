package org.bouncycastle.asn1.ocsp;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

public class OCSPResponseStatus
    extends ASN1Object
{
    public static final int SUCCESSFUL = 0;
    public static final int MALFORMED_REQUEST = 1;
    public static final int INTERNAL_ERROR = 2;
    public static final int TRY_LATER = 3;
    public static final int SIG_REQUIRED = 5;
    public static final int UNAUTHORIZED = 6;

    private ASN1Enumerated value;

    /**
     * The OCSPResponseStatus enumeration.
     * <pre>
     * OCSPResponseStatus ::= ENUMERATED {
     *     successful            (0),  --Response has valid confirmations
     *     malformedRequest      (1),  --Illegal confirmation request
     *     internalError         (2),  --Internal error in issuer
     *     tryLater              (3),  --Try again later
     *                                 --(4) is not used
     *     sigRequired           (5),  --Must sign the request
     *     unauthorized          (6)   --Request unauthorized
     * }
     * </pre>
     */
    public OCSPResponseStatus(
        int value)
    {
        this(new ASN1Enumerated(value));
    }

    private OCSPResponseStatus(
        ASN1Enumerated value)
    {
        this.value = value;
    }

    public static OCSPResponseStatus getInstance(
        Object  obj)
    {
        if (obj instanceof OCSPResponseStatus)
        {
            return (OCSPResponseStatus)obj;
        }
        else if (obj != null)
        {
            return new OCSPResponseStatus(ASN1Enumerated.getInstance(obj));
        }

        return null;
    }

    public BigInteger getValue()
    {
        return value.getValue();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return value;
    }
}
