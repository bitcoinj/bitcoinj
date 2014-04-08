package org.bouncycastle.asn1.x509;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * PKIX RFC-2459 - TBSCertList object.
 * <pre>
 * TBSCertList  ::=  SEQUENCE  {
 *      version                 Version OPTIONAL,
 *                                   -- if present, shall be v2
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      thisUpdate              Time,
 *      nextUpdate              Time OPTIONAL,
 *      revokedCertificates     SEQUENCE OF SEQUENCE  {
 *           userCertificate         CertificateSerialNumber,
 *           revocationDate          Time,
 *           crlEntryExtensions      Extensions OPTIONAL
 *                                         -- if present, shall be v2
 *                                }  OPTIONAL,
 *      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                         -- if present, shall be v2
 *                                }
 * </pre>
 */
public class TBSCertList
    extends ASN1Object
{
    public static class CRLEntry
        extends ASN1Object
    {
        ASN1Sequence  seq;

        Extensions    crlEntryExtensions;

        private CRLEntry(
            ASN1Sequence  seq)
        {
            if (seq.size() < 2 || seq.size() > 3)
            {
                throw new IllegalArgumentException("Bad sequence size: " + seq.size());
            }
            
            this.seq = seq;
        }

        public static CRLEntry getInstance(Object o)
        {
            if (o instanceof CRLEntry)
            {
                return ((CRLEntry)o);
            }
            else if (o != null)
            {
                return new CRLEntry(ASN1Sequence.getInstance(o));
            }

            return null;
        }

        public ASN1Integer getUserCertificate()
        {
            return ASN1Integer.getInstance(seq.getObjectAt(0));
        }

        public Time getRevocationDate()
        {
            return Time.getInstance(seq.getObjectAt(1));
        }

        public Extensions getExtensions()
        {
            if (crlEntryExtensions == null && seq.size() == 3)
            {
                crlEntryExtensions = Extensions.getInstance(seq.getObjectAt(2));
            }
            
            return crlEntryExtensions;
        }

        public ASN1Primitive toASN1Primitive()
        {
            return seq;
        }

        public boolean hasExtensions()
        {
            return seq.size() == 3;
        }
    }

    private class RevokedCertificatesEnumeration
        implements Enumeration
    {
        private final Enumeration en;

        RevokedCertificatesEnumeration(Enumeration en)
        {
            this.en = en;
        }

        public boolean hasMoreElements()
        {
            return en.hasMoreElements();
        }

        public Object nextElement()
        {
            return CRLEntry.getInstance(en.nextElement());
        }
    }

    private class EmptyEnumeration
        implements Enumeration
    {
        public boolean hasMoreElements()
        {
            return false;
        }

        public Object nextElement()
        {
            return null;   // TODO: check exception handling
        }
    }

    ASN1Integer             version;
    AlgorithmIdentifier     signature;
    X500Name                issuer;
    Time                    thisUpdate;
    Time                    nextUpdate;
    ASN1Sequence            revokedCertificates;
    Extensions              crlExtensions;

    public static TBSCertList getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static TBSCertList getInstance(
        Object  obj)
    {
        if (obj instanceof TBSCertList)
        {
            return (TBSCertList)obj;
        }
        else if (obj != null)
        {
            return new TBSCertList(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public TBSCertList(
        ASN1Sequence  seq)
    {
        if (seq.size() < 3 || seq.size() > 7)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        int seqPos = 0;

        if (seq.getObjectAt(seqPos) instanceof ASN1Integer)
        {
            version = ASN1Integer.getInstance(seq.getObjectAt(seqPos++));
        }
        else
        {
            version = null;  // version is optional
        }

        signature = AlgorithmIdentifier.getInstance(seq.getObjectAt(seqPos++));
        issuer = X500Name.getInstance(seq.getObjectAt(seqPos++));
        thisUpdate = Time.getInstance(seq.getObjectAt(seqPos++));

        if (seqPos < seq.size()
            && (seq.getObjectAt(seqPos) instanceof ASN1UTCTime
               || seq.getObjectAt(seqPos) instanceof ASN1GeneralizedTime
               || seq.getObjectAt(seqPos) instanceof Time))
        {
            nextUpdate = Time.getInstance(seq.getObjectAt(seqPos++));
        }

        if (seqPos < seq.size()
            && !(seq.getObjectAt(seqPos) instanceof DERTaggedObject))
        {
            revokedCertificates = ASN1Sequence.getInstance(seq.getObjectAt(seqPos++));
        }

        if (seqPos < seq.size()
            && seq.getObjectAt(seqPos) instanceof DERTaggedObject)
        {
            crlExtensions = Extensions.getInstance(ASN1Sequence.getInstance((ASN1TaggedObject)seq.getObjectAt(seqPos), true));
        }
    }

    public int getVersionNumber()
    {
        if (version == null)
        {
            return 1;
        }
        return version.getValue().intValue() + 1;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public AlgorithmIdentifier getSignature()
    {
        return signature;
    }

    public X500Name getIssuer()
    {
        return issuer;
    }

    public Time getThisUpdate()
    {
        return thisUpdate;
    }

    public Time getNextUpdate()
    {
        return nextUpdate;
    }

    public CRLEntry[] getRevokedCertificates()
    {
        if (revokedCertificates == null)
        {
            return new CRLEntry[0];
        }

        CRLEntry[] entries = new CRLEntry[revokedCertificates.size()];

        for (int i = 0; i < entries.length; i++)
        {
            entries[i] = CRLEntry.getInstance(revokedCertificates.getObjectAt(i));
        }
        
        return entries;
    }

    public Enumeration getRevokedCertificateEnumeration()
    {
        if (revokedCertificates == null)
        {
            return new EmptyEnumeration();
        }

        return new RevokedCertificatesEnumeration(revokedCertificates.getObjects());
    }

    public Extensions getExtensions()
    {
        return crlExtensions;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (version != null)
        {
            v.add(version);
        }
        v.add(signature);
        v.add(issuer);

        v.add(thisUpdate);
        if (nextUpdate != null)
        {
            v.add(nextUpdate);
        }

        // Add CRLEntries if they exist
        if (revokedCertificates != null)
        {
            v.add(revokedCertificates);
        }

        if (crlExtensions != null)
        {
            v.add(new DERTaggedObject(0, crlExtensions));
        }

        return new DERSequence(v);
    }
}
