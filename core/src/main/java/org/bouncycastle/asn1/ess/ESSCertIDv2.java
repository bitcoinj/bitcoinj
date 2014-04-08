package org.bouncycastle.asn1.ess;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.IssuerSerial;

public class ESSCertIDv2
    extends ASN1Object
{
    private AlgorithmIdentifier hashAlgorithm;
    private byte[]              certHash;
    private IssuerSerial        issuerSerial;
    private static final AlgorithmIdentifier DEFAULT_ALG_ID = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

    public static ESSCertIDv2 getInstance(
        Object o)
    {
        if (o instanceof ESSCertIDv2)
        {
            return (ESSCertIDv2) o;
        }
        else if (o != null)
        {
            return new ESSCertIDv2(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private ESSCertIDv2(
        ASN1Sequence seq)
    {
        if (seq.size() > 3)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        int count = 0;

        if (seq.getObjectAt(0) instanceof ASN1OctetString)
        {
            // Default value
            this.hashAlgorithm = DEFAULT_ALG_ID;
        }
        else
        {
            this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(count++).toASN1Primitive());
        }

        this.certHash = ASN1OctetString.getInstance(seq.getObjectAt(count++).toASN1Primitive()).getOctets();

        if (seq.size() > count)
        {
            this.issuerSerial = IssuerSerial.getInstance(seq.getObjectAt(count));
        }
    }

    public ESSCertIDv2(
        byte[]              certHash)
    {
        this(null, certHash, null);
    }

    public ESSCertIDv2(
        AlgorithmIdentifier algId,
        byte[]              certHash)
    {
        this(algId, certHash, null);
    }

    public ESSCertIDv2(
        byte[]              certHash,
        IssuerSerial        issuerSerial)
    {
        this(null, certHash, issuerSerial);
    }

    public ESSCertIDv2(
        AlgorithmIdentifier algId,
        byte[]              certHash,
        IssuerSerial        issuerSerial)
    {
        if (algId == null)
        {
            // Default value
            this.hashAlgorithm = DEFAULT_ALG_ID;
        }
        else
        {
            this.hashAlgorithm = algId;
        }

        this.certHash = certHash;
        this.issuerSerial = issuerSerial;
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        return this.hashAlgorithm;
    }

    public byte[] getCertHash()
    {
        return certHash;
    }

    public IssuerSerial getIssuerSerial()
    {
        return issuerSerial;
    }

    /**
     * <pre>
     * ESSCertIDv2 ::=  SEQUENCE {
     *     hashAlgorithm     AlgorithmIdentifier
     *              DEFAULT {algorithm id-sha256},
     *     certHash          Hash,
     *     issuerSerial      IssuerSerial OPTIONAL
     * }
     *
     * Hash ::= OCTET STRING
     *
     * IssuerSerial ::= SEQUENCE {
     *     issuer         GeneralNames,
     *     serialNumber   CertificateSerialNumber
     * }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (!hashAlgorithm.equals(DEFAULT_ALG_ID))
        {
            v.add(hashAlgorithm);
        }

        v.add(new DEROctetString(certHash).toASN1Primitive());

        if (issuerSerial != null)
        {
            v.add(issuerSerial);
        }

        return new DERSequence(v);
    }

}
