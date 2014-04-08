package org.bouncycastle.crypto.tls;

/**
 * RFC 5705
 */
public class ExporterLabel
{
    /*
     * RFC 5246
     */
    public static final String client_finished = "client finished";
    public static final String server_finished = "server finished";
    public static final String master_secret = "master secret";
    public static final String key_expansion = "key expansion";

    /*
     * RFC 5216
     */
    public static final String client_EAP_encryption = "client EAP encryption";

    /*
     * RFC 5281
     */
    public static final String ttls_keying_material = "ttls keying material";
    public static final String ttls_challenge = "ttls challenge";

    /*
     * RFC 5764
     */
    public static final String dtls_srtp = "EXTRACTOR-dtls_srtp";
}
