package com.google.bitcoin.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;

import com.google.bitcoin.bouncycastle.asn1.DERBitString;
import com.google.bitcoin.bouncycastle.asn1.x509.KeyUsage;
import com.google.bitcoin.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.google.bitcoin.bouncycastle.asn1.x509.X509CertificateStructure;
import com.google.bitcoin.bouncycastle.asn1.x509.X509Extension;
import com.google.bitcoin.bouncycastle.asn1.x509.X509Extensions;
import com.google.bitcoin.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.google.bitcoin.bouncycastle.crypto.CryptoException;
import com.google.bitcoin.bouncycastle.crypto.InvalidCipherTextException;
import com.google.bitcoin.bouncycastle.crypto.Signer;
import com.google.bitcoin.bouncycastle.crypto.agreement.DHBasicAgreement;
import com.google.bitcoin.bouncycastle.crypto.agreement.srp.SRP6Client;
import com.google.bitcoin.bouncycastle.crypto.digests.SHA1Digest;
import com.google.bitcoin.bouncycastle.crypto.encodings.PKCS1Encoding;
import com.google.bitcoin.bouncycastle.crypto.engines.RSABlindedEngine;
import com.google.bitcoin.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import com.google.bitcoin.bouncycastle.crypto.io.SignerInputStream;
import com.google.bitcoin.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.google.bitcoin.bouncycastle.crypto.params.DHKeyGenerationParameters;
import com.google.bitcoin.bouncycastle.crypto.params.DHParameters;
import com.google.bitcoin.bouncycastle.crypto.params.DHPublicKeyParameters;
import com.google.bitcoin.bouncycastle.crypto.params.DSAPublicKeyParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ParametersWithRandom;
import com.google.bitcoin.bouncycastle.crypto.params.RSAKeyParameters;
import com.google.bitcoin.bouncycastle.crypto.prng.ThreadedSeedGenerator;
import com.google.bitcoin.bouncycastle.crypto.util.PublicKeyFactory;
import com.google.bitcoin.bouncycastle.util.BigIntegers;

/**
 * An implementation of all high level protocols in TLS 1.0.
 */
public class TlsProtocolHandler
{
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private static final short RL_CHANGE_CIPHER_SPEC = 20;

    private static final short RL_ALERT = 21;

    private static final short RL_HANDSHAKE = 22;

    private static final short RL_APPLICATION_DATA = 23;

    /*
     hello_request(0), client_hello(1), server_hello(2),
     certificate(11), server_key_exchange (12),
     certificate_request(13), server_hello_done(14),
     certificate_verify(15), client_key_exchange(16),
     finished(20), (255)
     */

    private static final short HP_HELLO_REQUEST = 0;

    private static final short HP_CLIENT_HELLO = 1;

    private static final short HP_SERVER_HELLO = 2;

    private static final short HP_CERTIFICATE = 11;

    private static final short HP_SERVER_KEY_EXCHANGE = 12;

    private static final short HP_CERTIFICATE_REQUEST = 13;

    private static final short HP_SERVER_HELLO_DONE = 14;

    private static final short HP_CERTIFICATE_VERIFY = 15;

    private static final short HP_CLIENT_KEY_EXCHANGE = 16;

    private static final short HP_FINISHED = 20;

    /*
    * Our Connection states
    */

    private static final short CS_CLIENT_HELLO_SEND = 1;

    private static final short CS_SERVER_HELLO_RECEIVED = 2;

    private static final short CS_SERVER_CERTIFICATE_RECEIVED = 3;

    private static final short CS_SERVER_KEY_EXCHANGE_RECEIVED = 4;

    private static final short CS_CERTIFICATE_REQUEST_RECEIVED = 5;

    private static final short CS_SERVER_HELLO_DONE_RECEIVED = 6;

    private static final short CS_CLIENT_KEY_EXCHANGE_SEND = 7;

    private static final short CS_CLIENT_VERIFICATION_SEND = 8;

    private static final short CS_CLIENT_CHANGE_CIPHER_SPEC_SEND = 9;

    private static final short CS_CLIENT_FINISHED_SEND = 10;

    private static final short CS_SERVER_CHANGE_CIPHER_SPEC_RECEIVED = 11;

    private static final short CS_DONE = 12;


    protected static final short AP_close_notify = 0;
    protected static final short AP_unexpected_message = 10;
    protected static final short AP_bad_record_mac = 20;
    protected static final short AP_decryption_failed = 21;
    protected static final short AP_record_overflow = 22;
    protected static final short AP_decompression_failure = 30;
    protected static final short AP_handshake_failure = 40;
    protected static final short AP_bad_certificate = 42;
    protected static final short AP_unsupported_certificate = 43;
    protected static final short AP_certificate_revoked = 44;
    protected static final short AP_certificate_expired = 45;
    protected static final short AP_certificate_unknown = 46;
    protected static final short AP_illegal_parameter = 47;
    protected static final short AP_unknown_ca = 48;
    protected static final short AP_access_denied = 49;
    protected static final short AP_decode_error = 50;
    protected static final short AP_decrypt_error = 51;
    protected static final short AP_export_restriction = 60;
    protected static final short AP_protocol_version = 70;
    protected static final short AP_insufficient_security = 71;
    protected static final short AP_internal_error = 80;
    protected static final short AP_user_canceled = 90;
    protected static final short AP_no_renegotiation = 100;

    protected static final short AL_warning = 1;
    protected static final short AL_fatal = 2;

    private static final byte[] emptybuf = new byte[0];

    private static final String TLS_ERROR_MESSAGE = "Internal TLS error, this could be an attack";

    /*
    * Queues for data from some protocols.
    */

    private ByteQueue applicationDataQueue = new ByteQueue();

    private ByteQueue changeCipherSpecQueue = new ByteQueue();

    private ByteQueue alertQueue = new ByteQueue();

    private ByteQueue handshakeQueue = new ByteQueue();

    /*
    * The Record Stream we use
    */

    private RecordStream rs;

    private SecureRandom random;

    /*
    * The public key of the server.
    */

    private AsymmetricKeyParameter serverPublicKey = null;

    private TlsInputStream tlsInputStream = null;
    private TlsOuputStream tlsOutputStream = null;

    private boolean closed = false;
    private boolean failedWithError = false;
    private boolean appDataReady = false;
    private boolean extendedClientHello;

    private byte[] clientRandom;
    private byte[] serverRandom;
    private byte[] ms;

    private TlsCipherSuite chosenCipherSuite = null;

    private BigInteger SRP_A;
    private byte[] SRP_identity, SRP_password;
    private BigInteger Yc;
    private byte[] pms;

    private CertificateVerifyer verifyer = null;

    public TlsProtocolHandler(InputStream is, OutputStream os)
    {
        /*
         * We use our threaded seed generator to generate a good random
         * seed. If the user has a better random seed, he should use
         * the constructor with a SecureRandom.
         */
        ThreadedSeedGenerator tsg = new ThreadedSeedGenerator();
        this.random = new SecureRandom();
        /*
         * Hopefully, 20 bytes in fast mode are good enough.
         */
        this.random.setSeed(tsg.generateSeed(20, true));

        this.rs = new RecordStream(this, is, os);
    }

    public TlsProtocolHandler(InputStream is, OutputStream os, SecureRandom sr)
    {
        this.random = sr;
        this.rs = new RecordStream(this, is, os);
    }

    private short connection_state;

    protected void processData(short protocol, byte[] buf, int offset, int len)
        throws IOException
    {
        /*
         * Have a look at the protocol type, and add it to the correct queue.
         */
        switch (protocol)
        {
            case RL_CHANGE_CIPHER_SPEC:
                changeCipherSpecQueue.addData(buf, offset, len);
                processChangeCipherSpec();
                break;
            case RL_ALERT:
                alertQueue.addData(buf, offset, len);
                processAlert();
                break;
            case RL_HANDSHAKE:
                handshakeQueue.addData(buf, offset, len);
                processHandshake();
                break;
            case RL_APPLICATION_DATA:
                if (!appDataReady)
                {
                    this.failWithError(AL_fatal, AP_unexpected_message);
                }
                applicationDataQueue.addData(buf, offset, len);
                processApplicationData();
                break;
            default:
                /*
                * Uh, we don't know this protocol.
                *
                * RFC2246 defines on page 13, that we should ignore this.
                */

        }
    }

    private void processHandshake() throws IOException
    {
        boolean read;
        do
        {
            read = false;

            /*
            * We need the first 4 bytes, they contain type and length of
            * the message.
            */
            if (handshakeQueue.size() >= 4)
            {
                byte[] beginning = new byte[4];
                handshakeQueue.read(beginning, 0, 4, 0);
                ByteArrayInputStream bis = new ByteArrayInputStream(beginning);
                short type = TlsUtils.readUint8(bis);
                int len = TlsUtils.readUint24(bis);

                /*
                * Check if we have enough bytes in the buffer to read
                * the full message.
                */
                if (handshakeQueue.size() >= (len + 4))
                {
                    /*
                     * Read the message.
                     */
                    byte[] buf = new byte[len];
                    handshakeQueue.read(buf, 0, len, 4);
                    handshakeQueue.removeData(len + 4);

                    /*
                    * If it is not a finished message, update our hashes
                    * we prepare for the finish message.
                    */
                    if (type != HP_FINISHED)
                    {
                        rs.hash1.update(beginning, 0, 4);
                        rs.hash2.update(beginning, 0, 4);
                        rs.hash1.update(buf, 0, len);
                        rs.hash2.update(buf, 0, len);
                    }

                    /*
                    * Now, parse the message.
                    */
                    ByteArrayInputStream is = new ByteArrayInputStream(buf);

                    /*
                    * Check the type.
                    */
                    switch (type)
                    {
                        case HP_CERTIFICATE:
                        {
                            switch (connection_state)
                            {
                                case CS_SERVER_HELLO_RECEIVED:
                                {
                                    /*
                                    * Parse the certificates.
                                    */
                                    Certificate cert = Certificate.parse(is);
                                    assertEmpty(is);

                                    X509CertificateStructure x509Cert = cert.certs[0];
                                    SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();

                                    try
                                    {
                                        this.serverPublicKey = PublicKeyFactory.createKey(keyInfo);
                                    }
                                    catch (RuntimeException e)
                                    {
                                        this.failWithError(AL_fatal, AP_unsupported_certificate);
                                    }

                                    // Sanity check the PublicKeyFactory
                                    if (this.serverPublicKey.isPrivate())
                                    {
                                        this.failWithError(AL_fatal, AP_internal_error);
                                    }

                                    /*
                                     * Perform various checks per RFC2246 7.4.2
                                     * TODO "Unless otherwise specified, the signing algorithm for the certificate
                                     * must be the same as the algorithm for the certificate key."
                                     */
                                    switch (this.chosenCipherSuite.getKeyExchangeAlgorithm())
                                    {
                                        case TlsCipherSuite.KE_RSA:
                                            if (!(this.serverPublicKey instanceof RSAKeyParameters))
                                            {
                                                this.failWithError(AL_fatal, AP_certificate_unknown);
                                            }
                                            validateKeyUsage(x509Cert, KeyUsage.keyEncipherment);
                                            break;
                                        case TlsCipherSuite.KE_DHE_RSA:
                                        case TlsCipherSuite.KE_SRP_RSA:
                                            if (!(this.serverPublicKey instanceof RSAKeyParameters))
                                            {
                                                this.failWithError(AL_fatal, AP_certificate_unknown);
                                            }
                                            validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
                                            break;
                                        case TlsCipherSuite.KE_DHE_DSS:
                                        case TlsCipherSuite.KE_SRP_DSS:
                                            if (!(this.serverPublicKey instanceof DSAPublicKeyParameters))
                                            {
                                                this.failWithError(AL_fatal, AP_certificate_unknown);
                                            }
                                            break;
                                        default:
                                            this.failWithError(AL_fatal, AP_unsupported_certificate);
                                    }

                                    /*
                                     * Verify them.
                                     */
                                    if (!this.verifyer.isValid(cert.getCerts()))
                                    {
                                        this.failWithError(AL_fatal, AP_user_canceled);
                                    }

                                    break;
                                }
                                default:
                                    this.failWithError(AL_fatal, AP_unexpected_message);
                            }

                            connection_state = CS_SERVER_CERTIFICATE_RECEIVED;
                            read = true;
                            break;
                        }
                        case HP_FINISHED:
                            switch (connection_state)
                            {
                                case CS_SERVER_CHANGE_CIPHER_SPEC_RECEIVED:
                                    /*
                                    * Read the checksum from the finished message,
                                    * it has always 12 bytes.
                                    */
                                    byte[] receivedChecksum = new byte[12];
                                    TlsUtils.readFully(receivedChecksum, is);
                                    assertEmpty(is);

                                    /*
                                    * Calculate our own checksum.
                                    */
                                    byte[] checksum = new byte[12];
                                    byte[] md5andsha1 = new byte[16 + 20];
                                    rs.hash2.doFinal(md5andsha1, 0);
                                    TlsUtils.PRF(this.ms, TlsUtils.toByteArray("server finished"), md5andsha1, checksum);

                                    /*
                                    * Compare both checksums.
                                    */
                                    for (int i = 0; i < receivedChecksum.length; i++)
                                    {
                                        if (receivedChecksum[i] != checksum[i])
                                        {
                                            /*
                                            * Wrong checksum in the finished message.
                                            */
                                            this.failWithError(AL_fatal, AP_handshake_failure);
                                        }
                                    }

                                    connection_state = CS_DONE;

                                    /*
                                    * We are now ready to receive application data.
                                    */
                                    this.appDataReady = true;
                                    read = true;
                                    break;
                                default:
                                    this.failWithError(AL_fatal, AP_unexpected_message);
                            }
                            break;
                        case HP_SERVER_HELLO:
                            switch (connection_state)
                            {
                                case CS_CLIENT_HELLO_SEND:
                                    /*
                                    * Read the server hello message
                                    */
                                    TlsUtils.checkVersion(is, this);

                                    /*
                                    * Read the server random
                                    */
                                    this.serverRandom = new byte[32];
                                    TlsUtils.readFully(this.serverRandom, is);

                                    /*
                                    * Currently, we don't support session ids
                                    */
                                    byte[] sessionId = TlsUtils.readOpaque8(is);

                                    /*
                                    * Find out which ciphersuite the server has
                                    * chosen. If we don't support this ciphersuite,
                                    * the TlsCipherSuiteManager will throw an
                                    * exception.
                                    */
                                    this.chosenCipherSuite = TlsCipherSuiteManager.getCipherSuite(TlsUtils.readUint16(is), this);

                                    /*
                                    * We support only the null compression which
                                    * means no compression.
                                    */
                                    short compressionMethod = TlsUtils.readUint8(is);
                                    if (compressionMethod != 0)
                                    {
                                        this.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_illegal_parameter);
                                    }

                                    /*
                                     * RFC4366 2.2
                                     * The extended server hello message format MAY be sent
                                     * in place of the server hello message when the client
                                     * has requested extended functionality via the extended
                                     * client hello message specified in Section 2.1.
                                     */
                                    if (extendedClientHello && is.available() > 0)
                                    {
                                        // Process extensions from extended server hello
                                        byte[] extBytes = TlsUtils.readOpaque16(is);

                                        // Integer -> byte[]
                                        Hashtable serverExtensions = new Hashtable();

                                        ByteArrayInputStream ext = new ByteArrayInputStream(extBytes);
                                        while (ext.available() > 0)
                                        {
                                            int extType = TlsUtils.readUint16(ext);
                                            byte[] extValue = TlsUtils.readOpaque16(ext);

                                            serverExtensions.put(new Integer(extType), extValue);
                                        }

                                        // TODO Validate/process serverExtensions (via client?)
                                        // TODO[SRP]
                                    }

                                    assertEmpty(is);

                                    connection_state = CS_SERVER_HELLO_RECEIVED;
                                    read = true;
                                    break;
                                default:
                                    this.failWithError(AL_fatal, AP_unexpected_message);
                            }
                            break;
                        case HP_SERVER_HELLO_DONE:
                            switch (connection_state)
                            {

                                case CS_SERVER_CERTIFICATE_RECEIVED:
                                    /*
                                    * There was no server key exchange message, check
                                    * that we are doing RSA key exchange.
                                    */
                                    if (this.chosenCipherSuite.getKeyExchangeAlgorithm() != TlsCipherSuite.KE_RSA)
                                    {
                                        this.failWithError(AL_fatal, AP_unexpected_message);
                                    }

                                    /*
                                    * NB: Fall through to next case label to continue RSA key exchange
                                    */

                                case CS_SERVER_KEY_EXCHANGE_RECEIVED:
                                case CS_CERTIFICATE_REQUEST_RECEIVED:

                                    assertEmpty(is);
                                    boolean isCertReq = (connection_state == CS_CERTIFICATE_REQUEST_RECEIVED);
                                    connection_state = CS_SERVER_HELLO_DONE_RECEIVED;

                                    if (isCertReq)
                                    {
                                        sendClientCertificate();
                                    }

                                    /*
                                    * Send the client key exchange message, depending
                                    * on the key exchange we are using in our
                                    * ciphersuite.
                                    */
                                    switch (this.chosenCipherSuite.getKeyExchangeAlgorithm())
                                    {
                                        case TlsCipherSuite.KE_RSA:
                                        {
                                            /*
                                            * We are doing RSA key exchange. We will
                                            * choose a pre master secret and send it
                                            * rsa encrypted to the server.
                                            *
                                            * Prepare pre master secret.
                                            */
                                            pms = new byte[48];
                                            random.nextBytes(pms);
                                            pms[0] = 3;
                                            pms[1] = 1;

                                            /*
                                            * Encode the pms and send it to the server.
                                            *
                                            * Prepare an PKCS1Encoding with good random
                                            * padding.
                                            */
                                            RSABlindedEngine rsa = new RSABlindedEngine();
                                            PKCS1Encoding encoding = new PKCS1Encoding(rsa);
                                            encoding.init(true, new ParametersWithRandom(this.serverPublicKey, this.random));
                                            byte[] encrypted = null;
                                            try
                                            {
                                                encrypted = encoding.processBlock(pms, 0, pms.length);
                                            }
                                            catch (InvalidCipherTextException e)
                                            {
                                                /*
                                                * This should never happen, only during decryption.
                                                */
                                                this.failWithError(AL_fatal, AP_internal_error);
                                            }

                                            /*
                                            * Send the encrypted pms.
                                            */
                                            sendClientKeyExchange(encrypted);
                                            break;
                                        }
                                        case TlsCipherSuite.KE_DHE_DSS:
                                        case TlsCipherSuite.KE_DHE_RSA:
                                        {
                                            /*
                                            * Send the Client Key Exchange message for
                                            * DHE key exchange.
                                            */
                                            byte[] YcByte = BigIntegers.asUnsignedByteArray(this.Yc);

                                            sendClientKeyExchange(YcByte);

                                            break;
                                        }
                                        case TlsCipherSuite.KE_SRP:
                                        case TlsCipherSuite.KE_SRP_RSA:
                                        case TlsCipherSuite.KE_SRP_DSS:
                                        {
                                            /*
                                             * Send the Client Key Exchange message for
                                             * SRP key exchange.
                                             */
                                            byte[] bytes = BigIntegers.asUnsignedByteArray(this.SRP_A);

                                            sendClientKeyExchange(bytes);

                                            break;
                                        }
                                        default:
                                            /*
                                            * Problem during handshake, we don't know
                                            * how to handle this key exchange method.
                                            */
                                            this.failWithError(AL_fatal, AP_unexpected_message);

                                    }

                                    connection_state = CS_CLIENT_KEY_EXCHANGE_SEND;

                                    /*
                                    * Now, we send change cipher state
                                    */
                                    byte[] cmessage = new byte[1];
                                    cmessage[0] = 1;
                                    rs.writeMessage((short)RL_CHANGE_CIPHER_SPEC, cmessage, 0, cmessage.length);

                                    connection_state = CS_CLIENT_CHANGE_CIPHER_SPEC_SEND;

                                    /*
                                    * Calculate the ms
                                    */
                                    this.ms = new byte[48];
                                    byte[] random = new byte[clientRandom.length + serverRandom.length];
                                    System.arraycopy(clientRandom, 0, random, 0, clientRandom.length);
                                    System.arraycopy(serverRandom, 0, random, clientRandom.length, serverRandom.length);
                                    TlsUtils.PRF(pms, TlsUtils.toByteArray("master secret"), random, this.ms);

                                    /*
                                    * Initialize our cipher suite
                                    */
                                    rs.writeSuite = this.chosenCipherSuite;
                                    rs.writeSuite.init(this.ms, clientRandom, serverRandom);

                                    /*
                                    * Send our finished message.
                                    */
                                    byte[] checksum = new byte[12];
                                    byte[] md5andsha1 = new byte[16 + 20];
                                    rs.hash1.doFinal(md5andsha1, 0);
                                    TlsUtils.PRF(this.ms, TlsUtils.toByteArray("client finished"), md5andsha1, checksum);

                                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                                    TlsUtils.writeUint8(HP_FINISHED, bos);
                                    TlsUtils.writeUint24(12, bos);
                                    bos.write(checksum);
                                    byte[] message = bos.toByteArray();

                                    rs.writeMessage((short)RL_HANDSHAKE, message, 0, message.length);

                                    this.connection_state = CS_CLIENT_FINISHED_SEND;
                                    read = true;
                                    break;
                                default:
                                    this.failWithError(AL_fatal, AP_handshake_failure);
                            }
                            break;
                        case HP_SERVER_KEY_EXCHANGE:
                        {
                            switch (connection_state)
                            {
                                case CS_SERVER_HELLO_RECEIVED:
                                    /*
                                     * Check that we are doing SRP key exchange
                                     */
                                    if (this.chosenCipherSuite.getKeyExchangeAlgorithm() != TlsCipherSuite.KE_SRP)
                                    {
                                        this.failWithError(AL_fatal, AP_unexpected_message);
                                    }

                                    // NB: Fall through to next case label

                                case CS_SERVER_CERTIFICATE_RECEIVED:
                                {
                                    /*
                                     * Check that we are doing DHE key exchange
                                     */
                                    switch (this.chosenCipherSuite.getKeyExchangeAlgorithm())
                                    {
                                        case TlsCipherSuite.KE_DHE_RSA:
                                        {
                                            processDHEKeyExchange(is, new TlsRSASigner());
                                            break;
                                        }
                                        case TlsCipherSuite.KE_DHE_DSS:
                                        {
                                            processDHEKeyExchange(is, new TlsDSSSigner());
                                            break;
                                        }
                                        case TlsCipherSuite.KE_SRP:
                                        {
                                            processSRPKeyExchange(is, null);
                                            break;
                                        }
                                        case TlsCipherSuite.KE_SRP_RSA:
                                        {
                                            processSRPKeyExchange(is, new TlsRSASigner());
                                            break;
                                        }
                                        case TlsCipherSuite.KE_SRP_DSS:
                                        {
                                            processSRPKeyExchange(is, new TlsDSSSigner());
                                            break;
                                        }
                                        default:
                                            this.failWithError(AL_fatal, AP_unexpected_message);
                                    }
                                    break;
                                }
                                default:
                                    this.failWithError(AL_fatal, AP_unexpected_message);
                            }

                            this.connection_state = CS_SERVER_KEY_EXCHANGE_RECEIVED;
                            read = true;
                            break;
                        }
                        case HP_CERTIFICATE_REQUEST:
                        {
                            switch (connection_state)
                            {
                                case CS_SERVER_CERTIFICATE_RECEIVED:
                                    /*
                                    * There was no server key exchange message, check
                                    * that we are doing RSA key exchange.
                                    */
                                    if (this.chosenCipherSuite.getKeyExchangeAlgorithm() != TlsCipherSuite.KE_RSA)
                                    {
                                        this.failWithError(AL_fatal, AP_unexpected_message);
                                    }

                                    /*
                                    * NB: Fall through to next case label to continue RSA key exchange
                                    */

                                case CS_SERVER_KEY_EXCHANGE_RECEIVED:
                                {
                                    byte[] types = TlsUtils.readOpaque8(is);
                                    byte[] auths = TlsUtils.readOpaque8(is);

                                    // TODO Validate/process

                                    assertEmpty(is);
                                    break;
                                }
                                default:
                                    this.failWithError(AL_fatal, AP_unexpected_message);
                            }

                            this.connection_state = CS_CERTIFICATE_REQUEST_RECEIVED;
                            read = true;
                            break;
                        }
                        case HP_HELLO_REQUEST:
                        case HP_CLIENT_KEY_EXCHANGE:
                        case HP_CERTIFICATE_VERIFY:
                        case HP_CLIENT_HELLO:
                        default:
                            // We do not support this!
                            this.failWithError(AL_fatal, AP_unexpected_message);
                            break;
                    }
                }
            }
        }
        while (read);

    }

    private void processApplicationData()
    {
        /*
         * There is nothing we need to do here.
         * 
         * This function could be used for callbacks when application
         * data arrives in the future.
         */
    }

    private void processAlert() throws IOException
    {
        while (alertQueue.size() >= 2)
        {
            /*
             * An alert is always 2 bytes. Read the alert.
             */
            byte[] tmp = new byte[2];
            alertQueue.read(tmp, 0, 2, 0);
            alertQueue.removeData(2);
            short level = tmp[0];
            short description = tmp[1];
            if (level == AL_fatal)
            {
                /*
                 * This is a fatal error.
                 */
                this.failedWithError = true;
                this.closed = true;
                /*
                 * Now try to close the stream, ignore errors.
                 */
                try
                {
                    rs.close();
                }
                catch (Exception e)
                {

                }
                throw new IOException(TLS_ERROR_MESSAGE);
            }
            else
            {
                /*
                 * This is just a warning.
                 */
                if (description == AP_close_notify)
                {
                    /*
                     * Close notify
                     */
                    this.failWithError(AL_warning, AP_close_notify);
                }
                /*
                 * If it is just a warning, we continue.
                 */
            }
        }
    }

    /**
     * This method is called, when a change cipher spec message is received.
     *
     * @throws IOException If the message has an invalid content or the
     *                     handshake is not in the correct state.
     */
    private void processChangeCipherSpec() throws IOException
    {
        while (changeCipherSpecQueue.size() > 0)
        {
            /*
             * A change cipher spec message is only one byte with the value 1.
             */
            byte[] b = new byte[1];
            changeCipherSpecQueue.read(b, 0, 1, 0);
            changeCipherSpecQueue.removeData(1);
            if (b[0] != 1)
            {
                /*
                 * This should never happen.
                 */
                this.failWithError(AL_fatal, AP_unexpected_message);

            }
            else
            {
                /*
                 * Check if we are in the correct connection state.
                 */
                if (this.connection_state == CS_CLIENT_FINISHED_SEND)
                {
                    rs.readSuite = rs.writeSuite;
                    this.connection_state = CS_SERVER_CHANGE_CIPHER_SPEC_RECEIVED;
                }
                else
                {
                    /*
                     * We are not in the correct connection state.
                     */
                    this.failWithError(AL_fatal, AP_handshake_failure);
                }

            }
        }
    }

    private void processDHEKeyExchange(ByteArrayInputStream is, Signer signer)
        throws IOException
    {
        InputStream sigIn = is;
        if (signer != null)
        {
            signer.init(false, this.serverPublicKey);
            signer.update(this.clientRandom, 0, this.clientRandom.length);
            signer.update(this.serverRandom, 0, this.serverRandom.length);

            sigIn = new SignerInputStream(is, signer);
        }

        /*
         * Parse the Structure
         */
        byte[] pByte = TlsUtils.readOpaque16(sigIn);
        byte[] gByte = TlsUtils.readOpaque16(sigIn);
        byte[] YsByte = TlsUtils.readOpaque16(sigIn);

        if (signer != null)
        {
            byte[] sigByte = TlsUtils.readOpaque16(is);

             /*
              * Verify the Signature.
              */
             if (!signer.verifySignature(sigByte))
             {
                 this.failWithError(AL_fatal, AP_bad_certificate);
             }
         }

         this.assertEmpty(is);

         /*
         * Do the DH calculation.
         */
         BigInteger p = new BigInteger(1, pByte);
         BigInteger g = new BigInteger(1, gByte);
         BigInteger Ys = new BigInteger(1, YsByte);

         /*
          * Check the DH parameter values
          */
         if (!p.isProbablePrime(10))
         {
             this.failWithError(AL_fatal, AP_illegal_parameter);
         }
         if (g.compareTo(TWO) < 0 || g.compareTo(p.subtract(TWO)) > 0)
         {
             this.failWithError(AL_fatal, AP_illegal_parameter);
         }
         // TODO For static DH public values, see additional checks in RFC 2631 2.1.5 
         if (Ys.compareTo(TWO) < 0 || Ys.compareTo(p.subtract(ONE)) > 0)
         {
             this.failWithError(AL_fatal, AP_illegal_parameter);
         }

         /*
          * Diffie-Hellman basic key agreement
          */
         DHParameters dhParams = new DHParameters(p, g);

         // Generate a keypair
         DHBasicKeyPairGenerator dhGen = new DHBasicKeyPairGenerator();
         dhGen.init(new DHKeyGenerationParameters(random, dhParams));

         AsymmetricCipherKeyPair dhPair = dhGen.generateKeyPair();

         // Store the public value to send to server
         this.Yc = ((DHPublicKeyParameters)dhPair.getPublic()).getY();

         // Calculate the shared secret
         DHBasicAgreement dhAgree = new DHBasicAgreement();
         dhAgree.init(dhPair.getPrivate());

         BigInteger agreement = dhAgree.calculateAgreement(new DHPublicKeyParameters(Ys, dhParams));

         this.pms = BigIntegers.asUnsignedByteArray(agreement);
    }

    private void processSRPKeyExchange(ByteArrayInputStream is, Signer signer)
        throws IOException
    {
        InputStream sigIn = is;
        if (signer != null)
        {
            signer.init(false, this.serverPublicKey);
            signer.update(this.clientRandom, 0, this.clientRandom.length);
            signer.update(this.serverRandom, 0, this.serverRandom.length);
    
            sigIn = new SignerInputStream(is, signer);
        }
    
        /*
         * Parse the Structure
         */
        byte[] NByte = TlsUtils.readOpaque16(sigIn);
        byte[] gByte = TlsUtils.readOpaque16(sigIn);
        byte[] sByte = TlsUtils.readOpaque8(sigIn);
        byte[] BByte = TlsUtils.readOpaque16(sigIn);

        if (signer != null)
        {
            byte[] sigByte = TlsUtils.readOpaque16(is);

            /*
             * Verify the Signature.
             */
            if (!signer.verifySignature(sigByte))
            {
                this.failWithError(AL_fatal, AP_bad_certificate);
            }
        }
    
        this.assertEmpty(is);
    
        BigInteger N = new BigInteger(1, NByte);
        BigInteger g = new BigInteger(1, gByte);
        byte[] s = sByte;
        BigInteger B = new BigInteger(1, BByte);
    
        SRP6Client srpClient = new SRP6Client();
        srpClient.init(N, g, new SHA1Digest(), random);

        this.SRP_A = srpClient.generateClientCredentials(s, this.SRP_identity,
            this.SRP_password);
    
        try
        {
            BigInteger S = srpClient.calculateSecret(B);
            this.pms = BigIntegers.asUnsignedByteArray(S);
        }
        catch (CryptoException e)
        {
            this.failWithError(AL_fatal, AP_illegal_parameter);
        }
    }

    private void validateKeyUsage(X509CertificateStructure c, int keyUsageBits)
        throws IOException
    {
        X509Extensions exts = c.getTBSCertificate().getExtensions();
        if (exts != null)
        {
            X509Extension ext = exts.getExtension(X509Extensions.KeyUsage);
            if (ext != null)
            {
                DERBitString ku = KeyUsage.getInstance(ext);
                int bits = ku.getBytes()[0] & 0xff;
                if ((bits & keyUsageBits) != keyUsageBits)
                {
                    this.failWithError(AL_fatal, AP_certificate_unknown);
                }
            }
        }
    }

    private void sendClientCertificate() throws IOException
    {
        /*
         * just write back the "no client certificate" message
         * see also gnutls, auth_cert.c:643 (0B 00 00 03 00 00 00)
         */
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HP_CERTIFICATE, bos);
        TlsUtils.writeUint24(3, bos);
        TlsUtils.writeUint24(0, bos);
        byte[] message = bos.toByteArray();

        rs.writeMessage((short)RL_HANDSHAKE, message, 0, message.length);
    }

    private void sendClientKeyExchange(byte[] keData) throws IOException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HP_CLIENT_KEY_EXCHANGE, bos);
        TlsUtils.writeUint24(keData.length + 2, bos);
        TlsUtils.writeOpaque16(keData, bos);
        byte[] message = bos.toByteArray();

        rs.writeMessage((short)RL_HANDSHAKE, message, 0, message.length);
    }

    /**
     * Connects to the remote system.
     *
     * @param verifyer Will be used when a certificate is received to verify
     *                 that this certificate is accepted by the client.
     * @throws IOException If handshake was not successful.
     */
    public void connect(CertificateVerifyer verifyer) throws IOException
    {
        this.verifyer = verifyer;

        /*
        * Send Client hello
        *
        * First, generate some random data.
        */
        this.clientRandom = new byte[32];
        random.nextBytes(this.clientRandom);

        int t = (int)(System.currentTimeMillis() / 1000);
        this.clientRandom[0] = (byte)(t >> 24);
        this.clientRandom[1] = (byte)(t >> 16);
        this.clientRandom[2] = (byte)(t >> 8);
        this.clientRandom[3] = (byte)t;

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        TlsUtils.writeVersion(os);
        os.write(this.clientRandom);

        /*
        * Length of Session id
        */
        TlsUtils.writeUint8((short)0, os);

        /*
        * Cipher suites
        */
        TlsCipherSuiteManager.writeCipherSuites(os);

        /*
        * Compression methods, just the null method.
        */
        byte[] compressionMethods = new byte[]{0x00};
        TlsUtils.writeOpaque8(compressionMethods, os);

        /*
         * Extensions
         */
        // TODO Collect extensions from client
        // Integer -> byte[]
        Hashtable clientExtensions = new Hashtable();

        // TODO[SRP]
//        {
//            ByteArrayOutputStream srpData = new ByteArrayOutputStream();
//            TlsUtils.writeOpaque8(SRP_identity, srpData);
//
//            // TODO[SRP] RFC5054 2.8.1: ExtensionType.srp = 12
//            clientExtensions.put(Integer.valueOf(12), srpData.toByteArray());
//        }

        this.extendedClientHello = !clientExtensions.isEmpty();

        if (extendedClientHello)
        {
            ByteArrayOutputStream ext = new ByteArrayOutputStream();

            Enumeration keys = clientExtensions.keys();
            while (keys.hasMoreElements())
            {
                Integer extType = (Integer)keys.nextElement();
                byte[] extValue = (byte[])clientExtensions.get(extType);

                TlsUtils.writeUint16(extType.intValue(), ext);
                TlsUtils.writeOpaque16(extValue, ext);
            }

            TlsUtils.writeOpaque16(ext.toByteArray(), os);
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HP_CLIENT_HELLO, bos);
        TlsUtils.writeUint24(os.size(), bos);
        bos.write(os.toByteArray());
        byte[] message = bos.toByteArray();
        rs.writeMessage(RL_HANDSHAKE, message, 0, message.length);
        connection_state = CS_CLIENT_HELLO_SEND;

        /*
        * We will now read data, until we have completed the handshake.
        */
        while (connection_state != CS_DONE)
        {
            rs.readData();
        }

        this.tlsInputStream = new TlsInputStream(this);
        this.tlsOutputStream = new TlsOuputStream(this);
    }

    /**
     * Read data from the network. The method will return immediately, if there is
     * still some data left in the buffer, or block until some application
     * data has been read from the network.
     *
     * @param buf    The buffer where the data will be copied to.
     * @param offset The position where the data will be placed in the buffer.
     * @param len    The maximum number of bytes to read.
     * @return The number of bytes read.
     * @throws IOException If something goes wrong during reading data.
     */
    protected int readApplicationData(byte[] buf, int offset, int len) throws IOException
    {
        while (applicationDataQueue.size() == 0)
        {
            /*
             * We need to read some data.
             */
            if (this.failedWithError)
            {
                /*
                 * Something went terribly wrong, we should throw an IOException
                 */
                throw new IOException(TLS_ERROR_MESSAGE);
            }
            if (this.closed)
            {
                /*
                 * Connection has been closed, there is no more data to read.
                 */
                return -1;
            }

            try
            {
                rs.readData();
            }
            catch (IOException e)
            {
                if (!this.closed)
                {
                    this.failWithError(AL_fatal, AP_internal_error);
                }
                throw e;
            }
            catch (RuntimeException e)
            {
                if (!this.closed)
                {
                    this.failWithError(AL_fatal, AP_internal_error);
                }
                throw e;
            }
        }
        len = Math.min(len, applicationDataQueue.size());
        applicationDataQueue.read(buf, offset, len, 0);
        applicationDataQueue.removeData(len);
        return len;
    }

    /**
     * Send some application data to the remote system.
     * <p/>
     * The method will handle fragmentation internally.
     *
     * @param buf    The buffer with the data.
     * @param offset The position in the buffer where the data is placed.
     * @param len    The length of the data.
     * @throws IOException If something goes wrong during sending.
     */
    protected void writeData(byte[] buf, int offset, int len) throws IOException
    {
        if (this.failedWithError)
        {
            throw new IOException(TLS_ERROR_MESSAGE);
        }
        if (this.closed)
        {
            throw new IOException("Sorry, connection has been closed, you cannot write more data");
        }

        /*
        * Protect against known IV attack!
        *
        * DO NOT REMOVE THIS LINE, EXCEPT YOU KNOW EXACTLY WHAT
        * YOU ARE DOING HERE.
        */
        rs.writeMessage(RL_APPLICATION_DATA, emptybuf, 0, 0);

        do
        {
            /*
             * We are only allowed to write fragments up to 2^14 bytes.
             */
            int toWrite = Math.min(len, 1 << 14);

            try
            {
                rs.writeMessage(RL_APPLICATION_DATA, buf, offset, toWrite);
            }
            catch (IOException e)
            {
                if (!closed)
                {
                    this.failWithError(AL_fatal, AP_internal_error);
                }
                throw e;
            }
            catch (RuntimeException e)
            {
                if (!closed)
                {
                    this.failWithError(AL_fatal, AP_internal_error);
                }
                throw e;
            }


            offset += toWrite;
            len -= toWrite;
        }
        while (len > 0);

    }

    /** @deprecated use 'getOutputStream' instead */
    public TlsOuputStream getTlsOuputStream()
    {
        return this.tlsOutputStream;
    }

    /**
     * @return An OutputStream which can be used to send data.
     */
    public OutputStream getOutputStream()
    {
        return this.tlsOutputStream;
    }

    /** @deprecated use 'getInputStream' instead */
    public TlsInputStream getTlsInputStream()
    {
        return this.tlsInputStream;
    }

    /**
     * @return An InputStream which can be used to read data.
     */
    public InputStream getInputStream()
    {
        return this.tlsInputStream;
    }

    /**
     * Terminate this connection with an alert.
     * <p/>
     * Can be used for normal closure too.
     *
     * @param alertLevel       The level of the alert, an be AL_fatal or AL_warning.
     * @param alertDescription The exact alert message.
     * @throws IOException If alert was fatal.
     */
    protected void failWithError(short alertLevel, short alertDescription) throws IOException
    {
        /*
         * Check if the connection is still open.
         */
        if (!closed)
        {
            /*
             * Prepare the message
             */
            byte[] error = new byte[2];
            error[0] = (byte)alertLevel;
            error[1] = (byte)alertDescription;
            this.closed = true;

            if (alertLevel == AL_fatal)
            {
                /*
                 * This is a fatal message.
                 */
                this.failedWithError = true;
            }
            rs.writeMessage(RL_ALERT, error, 0, 2);
            rs.close();
            if (alertLevel == AL_fatal)
            {
                throw new IOException(TLS_ERROR_MESSAGE);
            }
        }
        else
        {
            throw new IOException(TLS_ERROR_MESSAGE);
        }
    }

    /**
     * Closes this connection.
     *
     * @throws IOException If something goes wrong during closing.
     */
    public void close() throws IOException
    {
        if (!closed)
        {
            this.failWithError((short)1, (short)0);
        }
    }

    /**
     * Make sure the InputStream is now empty. Fail otherwise.
     *
     * @param is The InputStream to check.
     * @throws IOException If is is not empty.
     */
    protected void assertEmpty(ByteArrayInputStream is) throws IOException
    {
        if (is.available() > 0)
        {
            this.failWithError(AL_fatal, AP_decode_error);
        }
    }

    protected void flush() throws IOException
    {
        rs.flush();
    }
}
