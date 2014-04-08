package org.bouncycastle.crypto.tls;

/**
 * RFC 2246 6.2.1
 */
public class ContentType
{
    public static final short change_cipher_spec = 20;
    public static final short alert = 21;
    public static final short handshake = 22;
    public static final short application_data = 23;
    public static final short heartbeat = 24;
}
