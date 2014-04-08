package org.bouncycastle.asn1.x509.qualified;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * The QCStatement object.
 * <pre>
 * QCStatement ::= SEQUENCE {
 *   statementId        OBJECT IDENTIFIER,
 *   statementInfo      ANY DEFINED BY statementId OPTIONAL} 
 * </pre>
 */

public class QCStatement 
    extends ASN1Object
    implements ETSIQCObjectIdentifiers, RFC3739QCObjectIdentifiers
{
    ASN1ObjectIdentifier qcStatementId;
    ASN1Encodable        qcStatementInfo;

    public static QCStatement getInstance(
        Object obj)
    {
        if (obj instanceof QCStatement)
        {
            return (QCStatement)obj;
        }
        if (obj != null)
        {
            return new QCStatement(ASN1Sequence.getInstance(obj));            
        }
        
        return null;
    }    
    
    private QCStatement(
        ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();

        // qcStatementId
        qcStatementId = ASN1ObjectIdentifier.getInstance(e.nextElement());
        // qcstatementInfo
        if (e.hasMoreElements())
        {
            qcStatementInfo = (ASN1Encodable) e.nextElement();
        }
    }    
    
    public QCStatement(
        ASN1ObjectIdentifier qcStatementId)
    {
        this.qcStatementId = qcStatementId;
        this.qcStatementInfo = null;
    }
    
    public QCStatement(
        ASN1ObjectIdentifier qcStatementId,
        ASN1Encodable       qcStatementInfo)
    {
        this.qcStatementId = qcStatementId;
        this.qcStatementInfo = qcStatementInfo;
    }    
        
    public ASN1ObjectIdentifier getStatementId()
    {
        return qcStatementId;
    }
    
    public ASN1Encodable getStatementInfo()
    {
        return qcStatementInfo;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(qcStatementId);       
        
        if (qcStatementInfo != null)
        {
            seq.add(qcStatementInfo);
        }

        return new DERSequence(seq);
    }
}
