package com.google.bitcoin.bouncycastle.crypto.tls;

import com.google.bitcoin.bouncycastle.crypto.digests.SHA1Digest;
import com.google.bitcoin.bouncycastle.crypto.engines.AESFastEngine;
import com.google.bitcoin.bouncycastle.crypto.engines.DESedeEngine;
import com.google.bitcoin.bouncycastle.crypto.modes.CBCBlockCipher;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A manager for ciphersuite. This class does manage all ciphersuites
 * which are used by MicroTLS.
 */
public class TlsCipherSuiteManager
{
    private static final int TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a;
    private static final int TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013;
    private static final int TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016;
    private static final int TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f;
    private static final int TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032;
    private static final int TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033;
    private static final int TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035;
    private static final int TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038;
    private static final int TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039;

//    private static final int TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0xC01A;    
//    private static final int TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0xC01B;
//    private static final int TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0xC01C;
//    private static final int TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xC01D;
//    private static final int TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xC01E;
//    private static final int TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0xC01F;
//    private static final int TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xC020;
//    private static final int TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xC021;
//    private static final int TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xC022;

    protected static void writeCipherSuites(OutputStream os) throws IOException
    {
        int[] suites = new int[]
        {
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,

//            TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
//            TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
//            TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
//            TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
//            TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
//            TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
//            TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
//            TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
//            TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
        };

       TlsUtils.writeUint16(2 * suites.length, os);
       for (int i = 0; i < suites.length; ++i)
       {
           TlsUtils.writeUint16(suites[i], os);
       }
    }

    protected static TlsCipherSuite getCipherSuite(int number, TlsProtocolHandler handler) throws IOException
    {
        switch (number)
        {
            case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
                return createDESedeCipherSuite(24, TlsCipherSuite.KE_RSA);

            case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
                return createDESedeCipherSuite(24, TlsCipherSuite.KE_DHE_DSS);

            case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
                return createDESedeCipherSuite(24, TlsCipherSuite.KE_DHE_RSA);

            case TLS_RSA_WITH_AES_128_CBC_SHA:
                return createAESCipherSuite(16, TlsCipherSuite.KE_RSA);

            case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
                return createAESCipherSuite(16, TlsCipherSuite.KE_DHE_DSS);

            case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
                return createAESCipherSuite(16, TlsCipherSuite.KE_DHE_RSA);

            case TLS_RSA_WITH_AES_256_CBC_SHA:
                return createAESCipherSuite(32, TlsCipherSuite.KE_RSA);

            case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
                return createAESCipherSuite(32, TlsCipherSuite.KE_DHE_DSS);

            case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                return createAESCipherSuite(32, TlsCipherSuite.KE_DHE_RSA);

//            case TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
//                return createDESedeCipherSuite(24, TlsCipherSuite.KE_SRP);
//
//            case TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
//                return createDESedeCipherSuite(24, TlsCipherSuite.KE_SRP_RSA);
//
//            case TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
//                return createDESedeCipherSuite(24, TlsCipherSuite.KE_SRP_DSS);
//
//            case TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
//                return createAESCipherSuite(16, TlsCipherSuite.KE_SRP);
//
//            case TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
//                return createAESCipherSuite(16, TlsCipherSuite.KE_SRP_RSA);
//
//            case TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
//                return createAESCipherSuite(16, TlsCipherSuite.KE_SRP_DSS);
//
//            case TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
//                return createAESCipherSuite(32, TlsCipherSuite.KE_SRP);
//
//            case TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
//                return createAESCipherSuite(32, TlsCipherSuite.KE_SRP_RSA);
//
//            case TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
//                return createAESCipherSuite(32, TlsCipherSuite.KE_SRP_DSS);

            default:
                handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_handshake_failure);

                /*
                * Unreachable Code, failWithError will always throw an exception!
                */
                return null;
        }
    }

    private static TlsCipherSuite createAESCipherSuite(int cipherKeySize, short keyExchange)
    {
        return new TlsBlockCipherCipherSuite(createAESCipher(), createAESCipher(),
            new SHA1Digest(), new SHA1Digest(), cipherKeySize, keyExchange);
    }

    private static TlsCipherSuite createDESedeCipherSuite(int cipherKeySize, short keyExchange)
    {
        return new TlsBlockCipherCipherSuite(createDESedeCipher(), createDESedeCipher(),
            new SHA1Digest(), new SHA1Digest(), cipherKeySize, keyExchange);
    }

    private static CBCBlockCipher createAESCipher()
    {
        return new CBCBlockCipher(new AESFastEngine());
    }
    
    private static CBCBlockCipher createDESedeCipher()
    {
        return new CBCBlockCipher(new DESedeEngine());
    }
}
