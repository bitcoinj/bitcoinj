package org.bouncycastle.crypto.tls;

public class HandshakeType
{
    /*
     * RFC 2246 7.4
     */
    public static final short hello_request = 0;
    public static final short client_hello = 1;
    public static final short server_hello = 2;
    public static final short certificate = 11;
    public static final short server_key_exchange = 12;
    public static final short certificate_request = 13;
    public static final short server_hello_done = 14;
    public static final short certificate_verify = 15;
    public static final short client_key_exchange = 16;
    public static final short finished = 20;

    /*
     * RFC 3546 2.4
     */
    public static final short certificate_url = 21;
    public static final short certificate_status = 22;

    /*
     *  (DTLS) RFC 4347 4.3.2
     */
    public static final short hello_verify_request = 3;

    /*
     * RFC 4680 
     */
    public static final short supplemental_data = 23;

    /*
     * RFC 5077 
     */
    public static final short session_ticket = 4;
}
