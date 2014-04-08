package org.bouncycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class Extensions
    extends ASN1Object
{
    private Hashtable extensions = new Hashtable();
    private Vector ordering = new Vector();

    public static Extensions getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Extensions getInstance(
        Object obj)
    {
        if (obj instanceof Extensions)
        {
            return (Extensions)obj;
        }
        else if (obj != null)
        {
            return new Extensions(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Constructor from ASN1Sequence.
     * <p/>
     * the extensions are a list of constructed sequences, either with (OID, OctetString) or (OID, Boolean, OctetString)
     */
    private Extensions(
        ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();

        while (e.hasMoreElements())
        {
            Extension ext = Extension.getInstance(e.nextElement());

            extensions.put(ext.getExtnId(), ext);
            ordering.addElement(ext.getExtnId());
        }
    }

    /**
     * Base Constructor
     *
     * @param extension a single extension.
     */
    public Extensions(
        Extension extension)
    {
        this.ordering.addElement(extension.getExtnId());
        this.extensions.put(extension.getExtnId(), extension);
    }

    /**
     * Base Constructor
     *
     * @param extensions an array of extensions.
     */
    public Extensions(
        Extension[] extensions)
    {
        for (int i = 0; i != extensions.length; i++)
        {
            Extension ext = extensions[i];

            this.ordering.addElement(ext.getExtnId());
            this.extensions.put(ext.getExtnId(), ext);
        }
    }

    /**
     * return an Enumeration of the extension field's object ids.
     */
    public Enumeration oids()
    {
        return ordering.elements();
    }

    /**
     * return the extension represented by the object identifier
     * passed in.
     *
     * @return the extension if it's present, null otherwise.
     */
    public Extension getExtension(
        ASN1ObjectIdentifier oid)
    {
        return (Extension)extensions.get(oid);
    }

    /**
     * return the parsed value of the extension represented by the object identifier
     * passed in.
     *
     * @return the parsed value of the extension if it's present, null otherwise.
     */
    public ASN1Encodable getExtensionParsedValue(ASN1ObjectIdentifier oid)
    {
        Extension ext = this.getExtension(oid);

        if (ext != null)
        {
            return ext.getParsedValue();
        }

        return null;
    }

    /**
     * <pre>
     *     Extensions        ::=   SEQUENCE SIZE (1..MAX) OF Extension
     *
     *     Extension         ::=   SEQUENCE {
     *        extnId            EXTENSION.&amp;id ({ExtensionSet}),
     *        critical          BOOLEAN DEFAULT FALSE,
     *        extnValue         OCTET STRING }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        Enumeration e = ordering.elements();

        while (e.hasMoreElements())
        {
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
            Extension ext = (Extension)extensions.get(oid);

            vec.add(ext);
        }

        return new DERSequence(vec);
    }

    public boolean equivalent(
        Extensions other)
    {
        if (extensions.size() != other.extensions.size())
        {
            return false;
        }

        Enumeration e1 = extensions.keys();

        while (e1.hasMoreElements())
        {
            Object key = e1.nextElement();

            if (!extensions.get(key).equals(other.extensions.get(key)))
            {
                return false;
            }
        }

        return true;
    }

    public ASN1ObjectIdentifier[] getExtensionOIDs()
    {
        return toOidArray(ordering);
    }

    public ASN1ObjectIdentifier[] getNonCriticalExtensionOIDs()
    {
        return getExtensionOIDs(false);
    }

    public ASN1ObjectIdentifier[] getCriticalExtensionOIDs()
    {
        return getExtensionOIDs(true);
    }

    private ASN1ObjectIdentifier[] getExtensionOIDs(boolean isCritical)
    {
        Vector oidVec = new Vector();

        for (int i = 0; i != ordering.size(); i++)
        {
            Object oid = ordering.elementAt(i);

            if (((Extension)extensions.get(oid)).isCritical() == isCritical)
            {
                oidVec.addElement(oid);
            }
        }

        return toOidArray(oidVec);
    }

    private ASN1ObjectIdentifier[] toOidArray(Vector oidVec)
    {
        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[oidVec.size()];

        for (int i = 0; i != oids.length; i++)
        {
            oids[i] = (ASN1ObjectIdentifier)oidVec.elementAt(i);
        }
        return oids;
    }
}
