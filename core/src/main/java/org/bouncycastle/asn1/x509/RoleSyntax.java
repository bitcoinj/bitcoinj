package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * Implementation of the RoleSyntax object as specified by the RFC3281.
 * 
 * <pre>
 * RoleSyntax ::= SEQUENCE {
 *                 roleAuthority  [0] GeneralNames OPTIONAL,
 *                 roleName       [1] GeneralName
 *           } 
 * </pre>
 */
public class RoleSyntax 
    extends ASN1Object
{
    private GeneralNames roleAuthority;
    private GeneralName roleName;

    /**
     * RoleSyntax factory method.
     * @param obj the object used to construct an instance of <code>
     * RoleSyntax</code>. It must be an instance of <code>RoleSyntax
     * </code> or <code>ASN1Sequence</code>.
     * @return the instance of <code>RoleSyntax</code> built from the
     * supplied object.
     * @throws java.lang.IllegalArgumentException if the object passed
     * to the factory is not an instance of <code>RoleSyntax</code> or
     * <code>ASN1Sequence</code>.
     */
    public static RoleSyntax getInstance(
        Object obj)
    {
        
        if (obj instanceof RoleSyntax)
        {
            return (RoleSyntax)obj;
        }
        else if (obj != null)
        {
            return new RoleSyntax(ASN1Sequence.getInstance(obj));
        }

        return null;
    }
    
    /**
     * Constructor.
     * @param roleAuthority the role authority of this RoleSyntax.
     * @param roleName    the role name of this RoleSyntax.
     */
    public RoleSyntax(
        GeneralNames roleAuthority,
        GeneralName roleName)
    {
        if(roleName == null || 
                roleName.getTagNo() != GeneralName.uniformResourceIdentifier ||
                ((ASN1String)roleName.getName()).getString().equals(""))
        {
            throw new IllegalArgumentException("the role name MUST be non empty and MUST " +
                    "use the URI option of GeneralName");
        }
        this.roleAuthority = roleAuthority;
        this.roleName = roleName;
    }
    
    /**
     * Constructor. Invoking this constructor is the same as invoking
     * <code>new RoleSyntax(null, roleName)</code>.
     * @param roleName    the role name of this RoleSyntax.
     */
    public RoleSyntax(
        GeneralName roleName)
    {
        this(null, roleName);
    }

    /**
     * Utility constructor. Takes a <code>String</code> argument representing
     * the role name, builds a <code>GeneralName</code> to hold the role name
     * and calls the constructor that takes a <code>GeneralName</code>.
     * @param roleName
     */
    public RoleSyntax(
        String roleName)
    {
        this(new GeneralName(GeneralName.uniformResourceIdentifier,
                (roleName == null)? "": roleName));
    }
    
    /**
     * Constructor that builds an instance of <code>RoleSyntax</code> by
     * extracting the encoded elements from the <code>ASN1Sequence</code>
     * object supplied.
     * @param seq    an instance of <code>ASN1Sequence</code> that holds
     * the encoded elements used to build this <code>RoleSyntax</code>.
     */
    private RoleSyntax(
        ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        for (int i = 0; i != seq.size(); i++)
        {
            ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
            switch (taggedObject.getTagNo())
            {
            case 0:
                roleAuthority = GeneralNames.getInstance(taggedObject, false);
                break;
            case 1:
                roleName = GeneralName.getInstance(taggedObject, true);
                break;
            default:
                throw new IllegalArgumentException("Unknown tag in RoleSyntax");
            }
        }
    }

    /**
     * Gets the role authority of this RoleSyntax.
     * @return    an instance of <code>GeneralNames</code> holding the
     * role authority of this RoleSyntax.
     */
    public GeneralNames getRoleAuthority()
    {
        return this.roleAuthority;
    }
    
    /**
     * Gets the role name of this RoleSyntax.
     * @return    an instance of <code>GeneralName</code> holding the
     * role name of this RoleSyntax.
     */
    public GeneralName getRoleName()
    {
        return this.roleName;
    }
    
    /**
     * Gets the role name as a <code>java.lang.String</code> object.
     * @return    the role name of this RoleSyntax represented as a 
     * <code>java.lang.String</code> object.
     */
    public String getRoleNameAsString()
    {
        ASN1String str = (ASN1String)this.roleName.getName();
        
        return str.getString();
    }
    
    /**
     * Gets the role authority as a <code>String[]</code> object.
     * @return the role authority of this RoleSyntax represented as a
     * <code>String[]</code> array.
     */
    public String[] getRoleAuthorityAsString() 
    {
        if(roleAuthority == null) 
        {
            return new String[0];
        }
        
        GeneralName[] names = roleAuthority.getNames();
        String[] namesString = new String[names.length];
        for(int i = 0; i < names.length; i++) 
        {
            ASN1Encodable value = names[i].getName();
            if(value instanceof ASN1String)
            {
                namesString[i] = ((ASN1String)value).getString();
            }
            else
            {
                namesString[i] = value.toString();
            }
        }
        return namesString;
    }
    
    /**
     * Implementation of the method <code>toASN1Object</code> as
     * required by the superclass <code>ASN1Encodable</code>.
     * 
     * <pre>
     * RoleSyntax ::= SEQUENCE {
     *                 roleAuthority  [0] GeneralNames OPTIONAL,
     *                 roleName       [1] GeneralName
     *           } 
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if(this.roleAuthority != null)
        {
            v.add(new DERTaggedObject(false, 0, roleAuthority));
        }
        v.add(new DERTaggedObject(true, 1, roleName));
        
        return new DERSequence(v);
    }
    
    public String toString() 
    {
        StringBuffer buff = new StringBuffer("Name: " + this.getRoleNameAsString() +
                " - Auth: ");
        if(this.roleAuthority == null || roleAuthority.getNames().length == 0)
        {
            buff.append("N/A");
        }
        else 
        {
            String[] names = this.getRoleAuthorityAsString();
            buff.append('[').append(names[0]);
            for(int i = 1; i < names.length; i++) 
            {
                    buff.append(", ").append(names[i]);
            }
            buff.append(']');
        }
        return buff.toString();
    }
}
