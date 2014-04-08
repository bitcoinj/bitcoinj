package org.bouncycastle.asn1.icao;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 *
 * { ISOITU(2) intorgs(23) icao(136) }
 */
public interface ICAOObjectIdentifiers
{
    //
    // base id
    //
    /**  2.23.136  */
    static final ASN1ObjectIdentifier    id_icao                   = new ASN1ObjectIdentifier("2.23.136");

    /**  2.23.136.1  */
    static final ASN1ObjectIdentifier    id_icao_mrtd              = id_icao.branch("1");
    /**  2.23.136.1.1  */
    static final ASN1ObjectIdentifier    id_icao_mrtd_security     = id_icao_mrtd.branch("1");

    /** LDS security object, see ICAO Doc 9303-Volume 2-Section IV-A3.2<p>
     *  2.23.136.1.1.1  */
    static final ASN1ObjectIdentifier    id_icao_ldsSecurityObject = id_icao_mrtd_security.branch("1");

    /** CSCA master list, see TR CSCA Countersigning and Master List issuance<p>
     * 2.23.136.1.1.2
     */
    static final ASN1ObjectIdentifier    id_icao_cscaMasterList    = id_icao_mrtd_security.branch("2");
    /** 2.23.136.1.1.3 */
    static final ASN1ObjectIdentifier    id_icao_cscaMasterListSigningKey = id_icao_mrtd_security.branch("3");

    /** document type list, see draft TR LDS and PKI Maintenance, par. 3.2.1 <p>
     * 2.23.136.1.1.4
     */
    static final ASN1ObjectIdentifier    id_icao_documentTypeList  = id_icao_mrtd_security.branch("4");

    /** Active Authentication protocol, see draft TR LDS and PKI Maintenance, par. 5.2.2<p>
     * 2.23.136.1.1.5
     */
    static final ASN1ObjectIdentifier    id_icao_aaProtocolObject  = id_icao_mrtd_security.branch("5");

    /** CSCA name change and key reoll-over, see draft TR LDS and PKI Maintenance, par. 3.2.1<p>
     * 2.23.136.1.1.6
     */
    static final ASN1ObjectIdentifier    id_icao_extensions        = id_icao_mrtd_security.branch("6");
    /** 2.23.136.1.1.6.1 */
    static final ASN1ObjectIdentifier    id_icao_extensions_namechangekeyrollover = id_icao_extensions.branch("1");
}
