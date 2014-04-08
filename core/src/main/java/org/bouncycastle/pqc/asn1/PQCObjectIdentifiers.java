package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * PQC:
 * <p>
 * { iso(1) identifier-organization(3) dod(6) internet(1) private(4) 1 8301 3 1 3 5 3 ... }
 */
public interface PQCObjectIdentifiers
{
    /** 1.3.6.1.4.1.8301.3.1.3.5.3.2 */
    public static final ASN1ObjectIdentifier rainbow = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.5.3.2");

    /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.1 */
    public static final ASN1ObjectIdentifier rainbowWithSha1   = rainbow.branch("1");
    /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.2 */
    public static final ASN1ObjectIdentifier rainbowWithSha224 = rainbow.branch("2");
    /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.3 */
    public static final ASN1ObjectIdentifier rainbowWithSha256 = rainbow.branch("3");
    /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.4 */
    public static final ASN1ObjectIdentifier rainbowWithSha384 = rainbow.branch("4");
    /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.5 */
    public static final ASN1ObjectIdentifier rainbowWithSha512 = rainbow.branch("5");

    /** 1.3.6.1.4.1.8301.3.1.3.3 */
    public static final ASN1ObjectIdentifier gmss = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.3");

    /** 1.3.6.1.4.1.8301.3.1.3.3.1 */
    public static final ASN1ObjectIdentifier gmssWithSha1   = gmss.branch("1");
    /** 1.3.6.1.4.1.8301.3.1.3.3.2 */
    public static final ASN1ObjectIdentifier gmssWithSha224 = gmss.branch("2");
    /** 1.3.6.1.4.1.8301.3.1.3.3.3 */
    public static final ASN1ObjectIdentifier gmssWithSha256 = gmss.branch("3");
    /** 1.3.6.1.4.1.8301.3.1.3.3.4 */
    public static final ASN1ObjectIdentifier gmssWithSha384 = gmss.branch("4");
    /** 1.3.6.1.4.1.8301.3.1.3.3.5 */
    public static final ASN1ObjectIdentifier gmssWithSha512 = gmss.branch("5");

    /** 1.3.6.1.4.1.8301.3.1.3.4.1 */
    public static final ASN1ObjectIdentifier mcEliece       = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.1");

    /** 1.3.6.1.4.1.8301.3.1.3.4.2 */
    public static final ASN1ObjectIdentifier mcElieceCca2   = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2");

}
