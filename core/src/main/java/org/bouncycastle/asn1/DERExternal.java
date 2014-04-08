package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Class representing the DER-type External
 */
public class DERExternal
    extends ASN1Primitive
{
    private ASN1ObjectIdentifier directReference;
    private ASN1Integer indirectReference;
    private ASN1Primitive dataValueDescriptor;
    private int encoding;
    private ASN1Primitive externalContent;
    
    public DERExternal(ASN1EncodableVector vector)
    {
        int offset = 0;

        ASN1Primitive enc = getObjFromVector(vector, offset);
        if (enc instanceof ASN1ObjectIdentifier)
        {
            directReference = (ASN1ObjectIdentifier)enc;
            offset++;
            enc = getObjFromVector(vector, offset);
        }
        if (enc instanceof ASN1Integer)
        {
            indirectReference = (ASN1Integer) enc;
            offset++;
            enc = getObjFromVector(vector, offset);
        }
        if (!(enc instanceof DERTaggedObject))
        {
            dataValueDescriptor = (ASN1Primitive) enc;
            offset++;
            enc = getObjFromVector(vector, offset);
        }

        if (vector.size() != offset + 1)
        {
            throw new IllegalArgumentException("input vector too large");
        }

        if (!(enc instanceof DERTaggedObject))
        {
            throw new IllegalArgumentException("No tagged object found in vector. Structure doesn't seem to be of type External");
        }
        DERTaggedObject obj = (DERTaggedObject)enc;
        setEncoding(obj.getTagNo());
        externalContent = obj.getObject();
    }

    private ASN1Primitive getObjFromVector(ASN1EncodableVector v, int index)
    {
        if (v.size() <= index)
        {
            throw new IllegalArgumentException("too few objects in input vector");
        }

        return v.get(index).toASN1Primitive();
    }
    /**
     * Creates a new instance of DERExternal
     * See X.690 for more informations about the meaning of these parameters
     * @param directReference The direct reference or <code>null</code> if not set.
     * @param indirectReference The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param externalData The external data in its encoded form.
     */
    public DERExternal(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor, DERTaggedObject externalData)
    {
        this(directReference, indirectReference, dataValueDescriptor, externalData.getTagNo(), externalData.toASN1Primitive());
    }

    /**
     * Creates a new instance of DERExternal.
     * See X.690 for more informations about the meaning of these parameters
     * @param directReference The direct reference or <code>null</code> if not set.
     * @param indirectReference The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param encoding The encoding to be used for the external data
     * @param externalData The external data
     */
    public DERExternal(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor, int encoding, ASN1Primitive externalData)
    {
        setDirectReference(directReference);
        setIndirectReference(indirectReference);
        setDataValueDescriptor(dataValueDescriptor);
        setEncoding(encoding);
        setExternalContent(externalData.toASN1Primitive());
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        int ret = 0;
        if (directReference != null)
        {
            ret = directReference.hashCode();
        }
        if (indirectReference != null)
        {
            ret ^= indirectReference.hashCode();
        }
        if (dataValueDescriptor != null)
        {
            ret ^= dataValueDescriptor.hashCode();
        }
        ret ^= externalContent.hashCode();
        return ret;
    }

    boolean isConstructed()
    {
        return true;
    }

    int encodedLength()
        throws IOException
    {
        return this.getEncoded().length;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Primitive#encode(org.bouncycastle.asn1.DEROutputStream)
     */
    void encode(ASN1OutputStream out)
        throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (directReference != null)
        {
            baos.write(directReference.getEncoded(ASN1Encoding.DER));
        }
        if (indirectReference != null)
        {
            baos.write(indirectReference.getEncoded(ASN1Encoding.DER));
        }
        if (dataValueDescriptor != null)
        {
            baos.write(dataValueDescriptor.getEncoded(ASN1Encoding.DER));
        }
        DERTaggedObject obj = new DERTaggedObject(true, encoding, externalContent);
        baos.write(obj.getEncoded(ASN1Encoding.DER));
        out.writeEncoded(BERTags.CONSTRUCTED, BERTags.EXTERNAL, baos.toByteArray());
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Primitive#asn1Equals(org.bouncycastle.asn1.ASN1Primitive)
     */
    boolean asn1Equals(ASN1Primitive o)
    {
        if (!(o instanceof DERExternal))
        {
            return false;
        }
        if (this == o)
        {
            return true;
        }
        DERExternal other = (DERExternal)o;
        if (directReference != null)
        {
            if (other.directReference == null || !other.directReference.equals(directReference))  
            {
                return false;
            }
        }
        if (indirectReference != null)
        {
            if (other.indirectReference == null || !other.indirectReference.equals(indirectReference))
            {
                return false;
            }
        }
        if (dataValueDescriptor != null)
        {
            if (other.dataValueDescriptor == null || !other.dataValueDescriptor.equals(dataValueDescriptor))
            {
                return false;
            }
        }
        return externalContent.equals(other.externalContent);
    }

    /**
     * Returns the data value descriptor
     * @return The descriptor
     */
    public ASN1Primitive getDataValueDescriptor()
    {
        return dataValueDescriptor;
    }

    /**
     * Returns the direct reference of the external element
     * @return The reference
     */
    public ASN1ObjectIdentifier getDirectReference()
    {
        return directReference;
    }

    /**
     * Returns the encoding of the content. Valid values are
     * <ul>
     * <li><code>0</code> single-ASN1-type</li>
     * <li><code>1</code> OCTET STRING</li>
     * <li><code>2</code> BIT STRING</li>
     * </ul>
     * @return The encoding
     */
    public int getEncoding()
    {
        return encoding;
    }
    
    /**
     * Returns the content of this element
     * @return The content
     */
    public ASN1Primitive getExternalContent()
    {
        return externalContent;
    }
    
    /**
     * Returns the indirect reference of this element
     * @return The reference
     */
    public ASN1Integer getIndirectReference()
    {
        return indirectReference;
    }
    
    /**
     * Sets the data value descriptor
     * @param dataValueDescriptor The descriptor
     */
    private void setDataValueDescriptor(ASN1Primitive dataValueDescriptor)
    {
        this.dataValueDescriptor = dataValueDescriptor;
    }

    /**
     * Sets the direct reference of the external element
     * @param directReferemce The reference
     */
    private void setDirectReference(ASN1ObjectIdentifier directReferemce)
    {
        this.directReference = directReferemce;
    }
    
    /**
     * Sets the encoding of the content. Valid values are
     * <ul>
     * <li><code>0</code> single-ASN1-type</li>
     * <li><code>1</code> OCTET STRING</li>
     * <li><code>2</code> BIT STRING</li>
     * </ul>
     * @param encoding The encoding
     */
    private void setEncoding(int encoding)
    {
        if (encoding < 0 || encoding > 2)
        {
            throw new IllegalArgumentException("invalid encoding value: " + encoding);
        }
        this.encoding = encoding;
    }
    
    /**
     * Sets the content of this element
     * @param externalContent The content
     */
    private void setExternalContent(ASN1Primitive externalContent)
    {
        this.externalContent = externalContent;
    }
    
    /**
     * Sets the indirect reference of this element
     * @param indirectReference The reference
     */
    private void setIndirectReference(ASN1Integer indirectReference)
    {
        this.indirectReference = indirectReference;
    }
}
