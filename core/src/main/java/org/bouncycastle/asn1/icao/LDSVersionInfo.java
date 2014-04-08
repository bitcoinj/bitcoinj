package org.bouncycastle.asn1.icao;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;

public class LDSVersionInfo
    extends ASN1Object
{
    private DERPrintableString ldsVersion;
    private DERPrintableString unicodeVersion;

    public LDSVersionInfo(String ldsVersion, String unicodeVersion)
    {
        this.ldsVersion = new DERPrintableString(ldsVersion);
        this.unicodeVersion = new DERPrintableString(unicodeVersion);
    }

    private LDSVersionInfo(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("sequence wrong size for LDSVersionInfo");
        }

        this.ldsVersion = DERPrintableString.getInstance(seq.getObjectAt(0));
        this.unicodeVersion = DERPrintableString.getInstance(seq.getObjectAt(1));
    }

    public static LDSVersionInfo getInstance(Object obj)
    {
        if (obj instanceof LDSVersionInfo)
        {
            return (LDSVersionInfo)obj;
        }
        else if (obj != null)
        {
            return new LDSVersionInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public String getLdsVersion()
    {
        return ldsVersion.getString();
    }

    public String getUnicodeVersion()
    {
        return unicodeVersion.getString();
    }

    /**
     * <pre>
     * LDSVersionInfo ::= SEQUENCE {
     *    ldsVersion PRINTABLE STRING
     *    unicodeVersion PRINTABLE STRING
     *  }
     * </pre>
     * @return
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(ldsVersion);
        v.add(unicodeVersion);

        return new DERSequence(v);
    }
}
