package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * The KeyPurposeId object.
 * <pre>
 *     KeyPurposeId ::= OBJECT IDENTIFIER
 *
 *     id-kp ::= OBJECT IDENTIFIER { iso(1) identified-organization(3) 
 *          dod(6) internet(1) security(5) mechanisms(5) pkix(7) 3}
 *
 * </pre>
 * To create a new KeyPurposeId where none of the below suit, use
 * <pre>
 *     ASN1ObjectIdentifier newKeyPurposeIdOID = new ASN1ObjectIdentifier("1.3.6.1...");
 *
 *     KeyPurposeId newKeyPurposeId = KeyPurposeId.getInstance(newKeyPurposeIdOID);
 * </pre>
 */
public class KeyPurposeId
    extends ASN1Object
{
    private static final ASN1ObjectIdentifier id_kp = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3");

    /**
     * { 2 5 29 37 0 }
     */
    public static final KeyPurposeId anyExtendedKeyUsage = new KeyPurposeId(Extension.extendedKeyUsage.branch("0"));

    /**
     * { id-kp 1 }
     */
    public static final KeyPurposeId id_kp_serverAuth = new KeyPurposeId(id_kp.branch("1"));
    /**
     * { id-kp 2 }
     */
    public static final KeyPurposeId id_kp_clientAuth = new KeyPurposeId(id_kp.branch("2"));
    /**
     * { id-kp 3 }
     */
    public static final KeyPurposeId id_kp_codeSigning = new KeyPurposeId(id_kp.branch("3"));
    /**
     * { id-kp 4 }
     */
    public static final KeyPurposeId id_kp_emailProtection = new KeyPurposeId(id_kp.branch("4"));
    /**
     * Usage deprecated by RFC4945 - was { id-kp 5 }
     */
    public static final KeyPurposeId id_kp_ipsecEndSystem = new KeyPurposeId(id_kp.branch("5"));
    /**
     * Usage deprecated by RFC4945 - was { id-kp 6 }
     */
    public static final KeyPurposeId id_kp_ipsecTunnel = new KeyPurposeId(id_kp.branch("6"));
    /**
     * Usage deprecated by RFC4945 - was { idkp 7 }
     */
    public static final KeyPurposeId id_kp_ipsecUser = new KeyPurposeId(id_kp.branch("7"));
    /**
     * { id-kp 8 }
     */
    public static final KeyPurposeId id_kp_timeStamping = new KeyPurposeId(id_kp.branch("8"));
    /**
     * { id-kp 9 }
     */
    public static final KeyPurposeId id_kp_OCSPSigning = new KeyPurposeId(id_kp.branch("9"));
    /**
     * { id-kp 10 }
     */
    public static final KeyPurposeId id_kp_dvcs = new KeyPurposeId(id_kp.branch("10"));
    /**
     * { id-kp 11 }
     */
    public static final KeyPurposeId id_kp_sbgpCertAAServerAuth = new KeyPurposeId(id_kp.branch("11"));
    /**
     * { id-kp 12 }
     */
    public static final KeyPurposeId id_kp_scvp_responder = new KeyPurposeId(id_kp.branch("12"));
    /**
     * { id-kp 13 }
     */
    public static final KeyPurposeId id_kp_eapOverPPP = new KeyPurposeId(id_kp.branch("13"));
    /**
     * { id-kp 14 }
     */
    public static final KeyPurposeId id_kp_eapOverLAN = new KeyPurposeId(id_kp.branch("14"));
    /**
     * { id-kp 15 }
     */
    public static final KeyPurposeId id_kp_scvpServer = new KeyPurposeId(id_kp.branch("15"));
    /**
     * { id-kp 16 }
     */
    public static final KeyPurposeId id_kp_scvpClient = new KeyPurposeId(id_kp.branch("16"));
    /**
     * { id-kp 17 }
     */
    public static final KeyPurposeId id_kp_ipsecIKE = new KeyPurposeId(id_kp.branch("17"));
    /**
     * { id-kp 18 }
     */
    public static final KeyPurposeId id_kp_capwapAC = new KeyPurposeId(id_kp.branch("18"));
    /**
     * { id-kp 19 }
     */
    public static final KeyPurposeId id_kp_capwapWTP = new KeyPurposeId(id_kp.branch("19"));

    //
    // microsoft key purpose ids
    //
    /**
     * { 1 3 6 1 4 1 311 20 2 2 }
     */
    public static final KeyPurposeId id_kp_smartcardlogon = new KeyPurposeId(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"));

    private ASN1ObjectIdentifier id;

    private KeyPurposeId(ASN1ObjectIdentifier id)
    {
        this.id = id;
    }

    /**
     * @deprecated use getInstance and an OID or one of the constants above.
     * @param id string representation of an OID.
     */
    public KeyPurposeId(String id)
    {
        this(new ASN1ObjectIdentifier(id));
    }

    public static KeyPurposeId getInstance(Object o)
    {
        if (o instanceof KeyPurposeId)
        {
            return (KeyPurposeId)o;
        }
        else if (o != null)
        {
            return new KeyPurposeId(ASN1ObjectIdentifier.getInstance(o));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return id;
    }

    public String getId()
    {
        return id.getId();
    }
}
