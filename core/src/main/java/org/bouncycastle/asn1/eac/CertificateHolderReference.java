package org.bouncycastle.asn1.eac;

import java.io.UnsupportedEncodingException;

public class CertificateHolderReference
{
    private static final String ReferenceEncoding = "ISO-8859-1";

    private String countryCode;
    private String holderMnemonic;
    private String sequenceNumber;

    public CertificateHolderReference(String countryCode, String holderMnemonic, String sequenceNumber)
    {
        this.countryCode = countryCode;
        this.holderMnemonic = holderMnemonic;
        this.sequenceNumber = sequenceNumber;
    }

    CertificateHolderReference(byte[] contents)
    {
        try
        {
            String concat = new String(contents, ReferenceEncoding);

            this.countryCode = concat.substring(0, 2);
            this.holderMnemonic = concat.substring(2, concat.length() - 5);

            this.sequenceNumber = concat.substring(concat.length() - 5);
        }
        catch (UnsupportedEncodingException e)
        {
            throw new IllegalStateException(e.toString());
        }
    }

    public String getCountryCode()
    {
        return countryCode;
    }

    public String getHolderMnemonic()
    {
        return holderMnemonic;
    }

    public String getSequenceNumber()
    {
        return sequenceNumber;
    }


    public byte[] getEncoded()
    {
        String ref = countryCode + holderMnemonic + sequenceNumber;

        try
        {
            return ref.getBytes(ReferenceEncoding);
        }
        catch (UnsupportedEncodingException e)
        {
            throw new IllegalStateException(e.toString());
        }
    }
}
