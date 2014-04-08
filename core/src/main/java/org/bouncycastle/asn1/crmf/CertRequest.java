package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class CertRequest
    extends ASN1Object
{
    private ASN1Integer certReqId;
    private CertTemplate certTemplate;
    private Controls controls;

    private CertRequest(ASN1Sequence seq)
    {
        certReqId = new ASN1Integer(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
        certTemplate = CertTemplate.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2)
        {
            controls = Controls.getInstance(seq.getObjectAt(2));
        }
    }

    public static CertRequest getInstance(Object o)
    {
        if (o instanceof CertRequest)
        {
            return (CertRequest)o;
        }
        else if (o != null)
        {
            return new CertRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertRequest(
        int certReqId,
        CertTemplate certTemplate,
        Controls controls)
    {
        this(new ASN1Integer(certReqId), certTemplate, controls);
    }

    public CertRequest(
        ASN1Integer certReqId,
        CertTemplate certTemplate,
        Controls controls)
    {
        this.certReqId = certReqId;
        this.certTemplate = certTemplate;
        this.controls = controls;
    }

    public ASN1Integer getCertReqId()
    {
        return certReqId;
    }

    public CertTemplate getCertTemplate()
    {
        return certTemplate;
    }

    public Controls getControls()
    {
        return controls;
    }

    /**
     * <pre>
     * CertRequest ::= SEQUENCE {
     *                      certReqId     INTEGER,          -- ID for matching request and reply
     *                      certTemplate  CertTemplate,  -- Selected fields of cert to be issued
     *                      controls      Controls OPTIONAL }   -- Attributes affecting issuance
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certReqId);
        v.add(certTemplate);

        if (controls != null)
        {
            v.add(controls);
        }

        return new DERSequence(v);
    }
}
