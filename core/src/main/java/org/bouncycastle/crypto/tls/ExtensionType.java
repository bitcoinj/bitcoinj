package org.bouncycastle.crypto.tls;

public class ExtensionType
{
    /*
     * RFC 2546 2.3.
     */
    public static final int server_name = 0;
    public static final int max_fragment_length = 1;
    public static final int client_certificate_url = 2;
    public static final int trusted_ca_keys = 3;
    public static final int truncated_hmac = 4;
    public static final int status_request = 5;

    /*
     * RFC 4681
     */
    public static final int user_mapping = 6;

    /*
     * RFC 4492 5.1.
     */
    public static final int elliptic_curves = 10;
    public static final int ec_point_formats = 11;

    /*
     * RFC 5054 2.8.1.
     */
    public static final int srp = 12;

    /*
     * RFC 5077 7.
     */
    public static final int session_ticket = 35;

    /*
     * RFC 5246 7.4.1.4.
     */
    public static final int signature_algorithms = 13;

    /*
     * RFC 5764 9.
     */
    public static final int use_srtp = 14;

    /*
     * RFC 6520 6.
     */
    public static final int heartbeat = 15;

    /*
     * draft-gutmann-tls-encrypt-then-mac-05
     * 
     * NOTE: This value has not yet been reserved by the IETF 
     */
    public static final int encrypt_then_mac = 66;

    /*
     * RFC 5746 3.2.
     */
    public static final int renegotiation_info = 0xff01;
}
