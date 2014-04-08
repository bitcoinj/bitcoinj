package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.Certificate;

public class CMPCertificate
    extends ASN1Object
    implements ASN1Choice
{
    private Certificate x509v3PKCert;
    private AttributeCertificate x509v2AttrCert;

    /**
     * Note: the addition of attribute certificates is a BC extension.
     */
    public CMPCertificate(AttributeCertificate x509v2AttrCert)
    {
        this.x509v2AttrCert = x509v2AttrCert;
    }

    public CMPCertificate(Certificate x509v3PKCert)
    {
        if (x509v3PKCert.getVersionNumber() != 3)
        {
            throw new IllegalArgumentException("only version 3 certificates allowed");
        }

        this.x509v3PKCert = x509v3PKCert;
    }

    public static CMPCertificate getInstance(Object o)
    {
        if (o == null || o instanceof CMPCertificate)
        {
            return (CMPCertificate)o;
        }

        if (o instanceof ASN1Sequence || o instanceof byte[])
        {
            return new CMPCertificate(Certificate.getInstance(o));
        }

        if (o instanceof ASN1TaggedObject)
        {
            return new CMPCertificate(AttributeCertificate.getInstance(((ASN1TaggedObject)o).getObject()));
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public boolean isX509v3PKCert()
    {
         return x509v3PKCert != null;
    }

    public Certificate getX509v3PKCert()
    {
        return x509v3PKCert;
    }

    public AttributeCertificate getX509v2AttrCert()
    {
        return x509v2AttrCert;
    }

    /**
     * <pre>
     * CMPCertificate ::= CHOICE {
     *            x509v3PKCert        Certificate
     *            x509v2AttrCert      [1] AttributeCertificate
     *  }
     * </pre>
     * Note: the addition of attribute certificates is a BC extension.
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        if (x509v2AttrCert != null)
        {        // explicit following CMP conventions
            return new DERTaggedObject(true, 1, x509v2AttrCert);
        }

        return x509v3PKCert.toASN1Primitive();
    }
}
