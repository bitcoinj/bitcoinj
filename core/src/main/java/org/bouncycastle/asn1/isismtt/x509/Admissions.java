package org.bouncycastle.asn1.isismtt.x509;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * An Admissions structure.
 * <pre>
 *            Admissions ::= SEQUENCE
 *            {
 *              admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
 *              namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
 *              professionInfos SEQUENCE OF ProfessionInfo
 *            }
 * </pre>
 *
 * @see org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax
 * @see org.bouncycastle.asn1.isismtt.x509.ProfessionInfo
 * @see org.bouncycastle.asn1.isismtt.x509.NamingAuthority
 */
public class Admissions 
    extends ASN1Object
{

    private GeneralName admissionAuthority;

    private NamingAuthority namingAuthority;

    private ASN1Sequence professionInfos;

    public static Admissions getInstance(Object obj)
    {
        if (obj == null || obj instanceof Admissions)
        {
            return (Admissions)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new Admissions((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Constructor from ASN1Sequence.
     * <p/>
     * The sequence is of type ProcurationSyntax:
     * <p/>
     * <pre>
     *            Admissions ::= SEQUENCE
     *            {
     *              admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
     *              namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
     *              professionInfos SEQUENCE OF ProfessionInfo
     *            }
     * </pre>
     *
     * @param seq The ASN.1 sequence.
     */
    private Admissions(ASN1Sequence seq)
    {
        if (seq.size() > 3)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }
        Enumeration e = seq.getObjects();

        ASN1Encodable o = (ASN1Encodable)e.nextElement();
        if (o instanceof ASN1TaggedObject)
        {
            switch (((ASN1TaggedObject)o).getTagNo())
            {
            case 0:
                admissionAuthority = GeneralName.getInstance((ASN1TaggedObject)o, true);
                break;
            case 1:
                namingAuthority = NamingAuthority.getInstance((ASN1TaggedObject)o, true);
                break;
            default:
                throw new IllegalArgumentException("Bad tag number: " + ((ASN1TaggedObject)o).getTagNo());
            }
            o = (ASN1Encodable)e.nextElement();
        }
        if (o instanceof ASN1TaggedObject)
        {
            switch (((ASN1TaggedObject)o).getTagNo())
            {
            case 1:
                namingAuthority = NamingAuthority.getInstance((ASN1TaggedObject)o, true);
                break;
            default:
                throw new IllegalArgumentException("Bad tag number: " + ((ASN1TaggedObject)o).getTagNo());
            }
            o = (ASN1Encodable)e.nextElement();
        }
        professionInfos = ASN1Sequence.getInstance(o);
        if (e.hasMoreElements())
        {
            throw new IllegalArgumentException("Bad object encountered: "
                + e.nextElement().getClass());
        }
    }

    /**
     * Constructor from a given details.
     * <p>
     * Parameter <code>professionInfos</code> is mandatory.
     *
     * @param admissionAuthority The admission authority.
     * @param namingAuthority    The naming authority.
     * @param professionInfos    The profession infos.
     */
    public Admissions(GeneralName admissionAuthority,
                      NamingAuthority namingAuthority, ProfessionInfo[] professionInfos)
    {
        this.admissionAuthority = admissionAuthority;
        this.namingAuthority = namingAuthority;
        this.professionInfos = new DERSequence(professionInfos);
    }

    public GeneralName getAdmissionAuthority()
    {
        return admissionAuthority;
    }

    public NamingAuthority getNamingAuthority()
    {
        return namingAuthority;
    }

    public ProfessionInfo[] getProfessionInfos()
    {
        ProfessionInfo[] infos = new ProfessionInfo[professionInfos.size()];
        int count = 0;
        for (Enumeration e = professionInfos.getObjects(); e.hasMoreElements();)
        {
            infos[count++] = ProfessionInfo.getInstance(e.nextElement());
        }
        return infos;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p>
     * Returns:
     * <pre>
     *       Admissions ::= SEQUENCE
     *       {
     *         admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
     *         namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
     *         professionInfos SEQUENCE OF ProfessionInfo
     *       }
     * </pre>
     *
     * @return an ASN1Primitive
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        
        if (admissionAuthority != null)
        {
            vec.add(new DERTaggedObject(true, 0, admissionAuthority));
        }
        if (namingAuthority != null)
        {
            vec.add(new DERTaggedObject(true, 1, namingAuthority));
        }
        vec.add(professionInfos);

        return new DERSequence(vec);
    }
}
