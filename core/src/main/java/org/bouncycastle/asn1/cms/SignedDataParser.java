package org.bouncycastle.asn1.cms;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.BERTags;

/**
 * Parser for <a href="http://tools.ietf.org/html/rfc5652#section-5.1">RFC 5652</a>: {@link SignedData} object.
 * <p>
 * <pre>
 * SignedData ::= SEQUENCE {
 *     version CMSVersion,
 *     digestAlgorithms DigestAlgorithmIdentifiers,
 *     encapContentInfo EncapsulatedContentInfo,
 *     certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *     crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 *     signerInfos SignerInfos
 *   }
 * </pre>
 */
public class SignedDataParser
{
    private ASN1SequenceParser _seq;
    private ASN1Integer         _version;
    private Object             _nextObject;
    private boolean            _certsCalled;
    private boolean            _crlsCalled;

    public static SignedDataParser getInstance(
        Object o)
        throws IOException
    {
        if (o instanceof ASN1Sequence)
        {
            return new SignedDataParser(((ASN1Sequence)o).parser());
        }
        if (o instanceof ASN1SequenceParser)
        {
            return new SignedDataParser((ASN1SequenceParser)o);
        }

        throw new IOException("unknown object encountered: " + o.getClass().getName());
    }

    private SignedDataParser(
        ASN1SequenceParser seq)
        throws IOException
    {
        this._seq = seq;
        this._version = (ASN1Integer)seq.readObject();
    }

    public ASN1Integer getVersion()
    {
        return _version;
    }

    public ASN1SetParser getDigestAlgorithms()
        throws IOException
    {
        Object o = _seq.readObject();

        if (o instanceof ASN1Set)
        {
            return ((ASN1Set)o).parser();
        }

        return (ASN1SetParser)o;
    }

    public ContentInfoParser getEncapContentInfo()
        throws IOException
    {
        return new ContentInfoParser((ASN1SequenceParser)_seq.readObject());
    }

    public ASN1SetParser getCertificates()
        throws IOException
    {
        _certsCalled = true;
        _nextObject = _seq.readObject();

        if (_nextObject instanceof ASN1TaggedObjectParser && ((ASN1TaggedObjectParser)_nextObject).getTagNo() == 0)
        {
            ASN1SetParser certs = (ASN1SetParser)((ASN1TaggedObjectParser)_nextObject).getObjectParser(BERTags.SET, false);
            _nextObject = null;

            return certs;
        }

        return null;
    }

    public ASN1SetParser getCrls()
        throws IOException
    {
        if (!_certsCalled)
        {
            throw new IOException("getCerts() has not been called.");
        }

        _crlsCalled = true;

        if (_nextObject == null)
        {
            _nextObject = _seq.readObject();
        }

        if (_nextObject instanceof ASN1TaggedObjectParser && ((ASN1TaggedObjectParser)_nextObject).getTagNo() == 1)
        {
            ASN1SetParser crls = (ASN1SetParser)((ASN1TaggedObjectParser)_nextObject).getObjectParser(BERTags.SET, false);
            _nextObject = null;

            return crls;
        }

        return null;
    }

    public ASN1SetParser getSignerInfos()
        throws IOException
    {
        if (!_certsCalled || !_crlsCalled)
        {
            throw new IOException("getCerts() and/or getCrls() has not been called.");
        }

        if (_nextObject == null)
        {
            _nextObject = _seq.readObject();
        }

        return (ASN1SetParser)_nextObject;
    }
}
