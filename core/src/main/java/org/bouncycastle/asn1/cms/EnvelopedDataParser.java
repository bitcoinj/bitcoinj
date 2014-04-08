package org.bouncycastle.asn1.cms;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.BERTags;

/** 
 * Parser of <a href="http://tools.ietf.org/html/rfc5652#section-6.1">RFC 5652</a> {@link EnvelopedData} object.
 * <p>
 * <pre>
 * EnvelopedData ::= SEQUENCE {
 *     version CMSVersion,
 *     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *     recipientInfos RecipientInfos,
 *     encryptedContentInfo EncryptedContentInfo,
 *     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL 
 * }
 * </pre>
 */
public class EnvelopedDataParser
{
    private ASN1SequenceParser _seq;
    private ASN1Integer        _version;
    private ASN1Encodable      _nextObject;
    private boolean            _originatorInfoCalled;
    
    public EnvelopedDataParser(
        ASN1SequenceParser seq)
        throws IOException
    {
        this._seq = seq;
        this._version = ASN1Integer.getInstance(seq.readObject());
    }

    public ASN1Integer getVersion()
    {
        return _version;
    }

    public OriginatorInfo getOriginatorInfo() 
        throws IOException
    {
        _originatorInfoCalled = true; 
        
        if (_nextObject == null)
        {
            _nextObject = _seq.readObject();
        }
        
        if (_nextObject instanceof ASN1TaggedObjectParser && ((ASN1TaggedObjectParser)_nextObject).getTagNo() == 0)
        {
            ASN1SequenceParser originatorInfo = (ASN1SequenceParser) ((ASN1TaggedObjectParser)_nextObject).getObjectParser(BERTags.SEQUENCE, false);
            _nextObject = null;
            return OriginatorInfo.getInstance(originatorInfo.toASN1Primitive());
        }
        
        return null;
    }
    
    public ASN1SetParser getRecipientInfos()
        throws IOException
    {
        if (!_originatorInfoCalled)
        {
            getOriginatorInfo();
        }
        
        if (_nextObject == null)
        {
            _nextObject = _seq.readObject();
        }
        
        ASN1SetParser recipientInfos = (ASN1SetParser)_nextObject;
        _nextObject = null;
        return recipientInfos;
    }

    public EncryptedContentInfoParser getEncryptedContentInfo() 
        throws IOException
    {
        if (_nextObject == null)
        {
            _nextObject = _seq.readObject();
        }
        
        
        if (_nextObject != null)
        {
            ASN1SequenceParser o = (ASN1SequenceParser) _nextObject;
            _nextObject = null;
            return new EncryptedContentInfoParser(o);
        }
        
        return null;
    }

    public ASN1SetParser getUnprotectedAttrs()
        throws IOException
    {
        if (_nextObject == null)
        {
            _nextObject = _seq.readObject();
        }
        
        
        if (_nextObject != null)
        {
            ASN1Encodable o = _nextObject;
            _nextObject = null;
            return (ASN1SetParser)((ASN1TaggedObjectParser)o).getObjectParser(BERTags.SET, false);
        }
        
        return null;
    }
}
