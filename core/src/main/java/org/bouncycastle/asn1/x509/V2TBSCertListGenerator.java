package org.bouncycastle.asn1.x509;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * Generator for Version 2 TBSCertList structures.
 * <pre>
 *  TBSCertList  ::=  SEQUENCE  {
 *       version                 Version OPTIONAL,
 *                                    -- if present, shall be v2
 *       signature               AlgorithmIdentifier,
 *       issuer                  Name,
 *       thisUpdate              Time,
 *       nextUpdate              Time OPTIONAL,
 *       revokedCertificates     SEQUENCE OF SEQUENCE  {
 *            userCertificate         CertificateSerialNumber,
 *            revocationDate          Time,
 *            crlEntryExtensions      Extensions OPTIONAL
 *                                          -- if present, shall be v2
 *                                 }  OPTIONAL,
 *       crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                          -- if present, shall be v2
 *                                 }
 * </pre>
 *
 * <b>Note: This class may be subject to change</b>
 */
public class V2TBSCertListGenerator
{
    private ASN1Integer         version = new ASN1Integer(1);
    private AlgorithmIdentifier signature;
    private X500Name            issuer;
    private Time                thisUpdate, nextUpdate=null;
    private Extensions          extensions = null;
    private ASN1EncodableVector crlentries = new ASN1EncodableVector();

    private final static ASN1Sequence[] reasons;

    static
    {
       reasons = new ASN1Sequence[11];

        reasons[0] = createReasonExtension(CRLReason.unspecified);
        reasons[1] = createReasonExtension(CRLReason.keyCompromise);
        reasons[2] = createReasonExtension(CRLReason.cACompromise);
        reasons[3] = createReasonExtension(CRLReason.affiliationChanged);
        reasons[4] = createReasonExtension(CRLReason.superseded);
        reasons[5] = createReasonExtension(CRLReason.cessationOfOperation);
        reasons[6] = createReasonExtension(CRLReason.certificateHold);
        reasons[7] = createReasonExtension(7); // 7 -> unknown
        reasons[8] = createReasonExtension(CRLReason.removeFromCRL);
        reasons[9] = createReasonExtension(CRLReason.privilegeWithdrawn);
        reasons[10] = createReasonExtension(CRLReason.aACompromise);
    }

    public V2TBSCertListGenerator()
    {
    }


    public void setSignature(
        AlgorithmIdentifier    signature)
    {
        this.signature = signature;
    }

    /**
     * @deprecated use X500Name method
     */
    public void setIssuer(
        X509Name    issuer)
    {
        this.issuer = X500Name.getInstance(issuer.toASN1Primitive());
    }

    public void setIssuer(X500Name issuer)
    {
        this.issuer = issuer;
    }

    public void setThisUpdate(
        ASN1UTCTime thisUpdate)
    {
        this.thisUpdate = new Time(thisUpdate);
    }

    public void setNextUpdate(
        ASN1UTCTime nextUpdate)
    {
        this.nextUpdate = new Time(nextUpdate);
    }

    public void setThisUpdate(
        Time thisUpdate)
    {
        this.thisUpdate = thisUpdate;
    }

    public void setNextUpdate(
        Time nextUpdate)
    {
        this.nextUpdate = nextUpdate;
    }

    public void addCRLEntry(
        ASN1Sequence crlEntry)
    {
        crlentries.add(crlEntry);
    }

    public void addCRLEntry(ASN1Integer userCertificate, ASN1UTCTime revocationDate, int reason)
    {
        addCRLEntry(userCertificate, new Time(revocationDate), reason);
    }

    public void addCRLEntry(ASN1Integer userCertificate, Time revocationDate, int reason)
    {
        addCRLEntry(userCertificate, revocationDate, reason, null);
    }

    public void addCRLEntry(ASN1Integer userCertificate, Time revocationDate, int reason, ASN1GeneralizedTime invalidityDate)
    {
        if (reason != 0)
        {
            ASN1EncodableVector v = new ASN1EncodableVector();

            if (reason < reasons.length)
            {
                if (reason < 0)
                {
                    throw new IllegalArgumentException("invalid reason value: " + reason);
                }
                v.add(reasons[reason]);
            }
            else
            {
                v.add(createReasonExtension(reason));
            }

            if (invalidityDate != null)
            {
                v.add(createInvalidityDateExtension(invalidityDate));
            }

            internalAddCRLEntry(userCertificate, revocationDate, new DERSequence(v));
        }
        else if (invalidityDate != null)
        {
            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(createInvalidityDateExtension(invalidityDate));

            internalAddCRLEntry(userCertificate, revocationDate, new DERSequence(v));
        }
        else
        {
            addCRLEntry(userCertificate, revocationDate, null);
        }
    }

    private void internalAddCRLEntry(ASN1Integer userCertificate, Time revocationDate, ASN1Sequence extensions)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(userCertificate);
        v.add(revocationDate);

        if (extensions != null)
        {
            v.add(extensions);
        }

        addCRLEntry(new DERSequence(v));
    }

    public void addCRLEntry(ASN1Integer userCertificate, Time revocationDate, Extensions extensions)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(userCertificate);
        v.add(revocationDate);
        
        if (extensions != null)
        {
            v.add(extensions);
        }
        
        addCRLEntry(new DERSequence(v));
    }

    public void setExtensions(
        X509Extensions    extensions)
    {
        setExtensions(Extensions.getInstance(extensions));
    }

    public void setExtensions(
        Extensions    extensions)
    {
        this.extensions = extensions;
    }

    public TBSCertList generateTBSCertList()
    {
        if ((signature == null) || (issuer == null) || (thisUpdate == null))
        {
            throw new IllegalStateException("Not all mandatory fields set in V2 TBSCertList generator.");
        }

        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(version);
        v.add(signature);
        v.add(issuer);

        v.add(thisUpdate);
        if (nextUpdate != null)
        {
            v.add(nextUpdate);
        }

        // Add CRLEntries if they exist
        if (crlentries.size() != 0)
        {
            v.add(new DERSequence(crlentries));
        }

        if (extensions != null)
        {
            v.add(new DERTaggedObject(0, extensions));
        }

        return new TBSCertList(new DERSequence(v));
    }

    private static ASN1Sequence createReasonExtension(int reasonCode)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        CRLReason crlReason = CRLReason.lookup(reasonCode);

        try
        {
            v.add(Extension.reasonCode);
            v.add(new DEROctetString(crlReason.getEncoded()));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e);
        }

        return new DERSequence(v);
    }

    private static ASN1Sequence createInvalidityDateExtension(ASN1GeneralizedTime invalidityDate)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        try
        {
            v.add(Extension.invalidityDate);
            v.add(new DEROctetString(invalidityDate.getEncoded()));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e);
        }

        return new DERSequence(v);
    }
}
