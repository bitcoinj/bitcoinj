package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;

/**
 * The KeyUsage object.
 * <pre>
 *    id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
 *
 *    KeyUsage ::= BIT STRING {
 *         digitalSignature        (0),
 *         nonRepudiation          (1),
 *         keyEncipherment         (2),
 *         dataEncipherment        (3),
 *         keyAgreement            (4),
 *         keyCertSign             (5),
 *         cRLSign                 (6),
 *         encipherOnly            (7),
 *         decipherOnly            (8) }
 * </pre>
 */
public class KeyUsage
    extends ASN1Object
{
    public static final int        digitalSignature = (1 << 7); 
    public static final int        nonRepudiation   = (1 << 6);
    public static final int        keyEncipherment  = (1 << 5);
    public static final int        dataEncipherment = (1 << 4);
    public static final int        keyAgreement     = (1 << 3);
    public static final int        keyCertSign      = (1 << 2);
    public static final int        cRLSign          = (1 << 1);
    public static final int        encipherOnly     = (1 << 0);
    public static final int        decipherOnly     = (1 << 15);

    private DERBitString bitString;

    public static KeyUsage getInstance(Object obj)   // needs to be DERBitString for other VMs
    {
        if (obj instanceof KeyUsage)
        {
            return (KeyUsage)obj;
        }
        else if (obj != null)
        {
            return new KeyUsage(DERBitString.getInstance(obj));
        }

        return null;
    }

    public static KeyUsage fromExtensions(Extensions extensions)
    {
        return KeyUsage.getInstance(extensions.getExtensionParsedValue(Extension.keyUsage));
    }

    /**
     * Basic constructor.
     * 
     * @param usage - the bitwise OR of the Key Usage flags giving the
     * allowed uses for the key.
     * e.g. (KeyUsage.keyEncipherment | KeyUsage.dataEncipherment)
     */
    public KeyUsage(
        int usage)
    {
        this.bitString = new DERBitString(usage);
    }

    private KeyUsage(
        DERBitString bitString)
    {
        this.bitString = bitString;
    }

    /**
     * Return true if a given usage bit is set, false otherwise.
     *
     * @param usages combination of usage flags.
     * @return true if all bits are set, false otherwise.
     */
    public boolean hasUsages(int usages)
    {
        return (bitString.intValue() & usages) == usages;
    }

    public byte[] getBytes()
    {
        return bitString.getBytes();
    }

    public int getPadBits()
    {
        return bitString.getPadBits();
    }

    public String toString()
    {
        byte[] data = bitString.getBytes();

        if (data.length == 1)
        {
            return "KeyUsage: 0x" + Integer.toHexString(data[0] & 0xff);
        }
        return "KeyUsage: 0x" + Integer.toHexString((data[1] & 0xff) << 8 | (data[0] & 0xff));
    }

    public ASN1Primitive toASN1Primitive()
    {
        return bitString;
    }
}
