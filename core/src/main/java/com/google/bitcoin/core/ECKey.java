/**
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.bitcoin.core;

import org.spongycastle.asn1.*;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.signers.ECDSASigner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import static com.google.common.base.Preconditions.checkArgument;

// TODO: This class is quite a mess by now. Once users are migrated away from Java serialization for the wallets,
// refactor this to have better internal layout and a more consistent API.

/**
 * Represents an elliptic curve keypair that we own and can use for signing transactions. Currently,
 * Bouncy Castle is used. In future this may become an interface with multiple implementations using different crypto
 * libraries. The class also provides a static method that can verify a signature with just the public key.<p>
 */
public class ECKey implements Serializable {
    private static final ECDomainParameters ecParams;

    private static final SecureRandom secureRandom;
    private static final long serialVersionUID = -728224901792295832L;

    /** How many bytes a Bitcoin public key is: 65, that is, two 32 byte co-ordinates plus a one byte header. */
    public static final int PUBLIC_KEY_LENGTH = 65;

    static {
        // All clients must agree on the curve to use by agreement. Bitcoin uses secp256k1.
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        secureRandom = new SecureRandom();
    }

    // The two parts of the key. If "priv" is set, "pub" can always be calculated. If "pub" is set but not "priv", we
    // can only verify signatures not make them.
    // TODO: Redesign this class to use consistent internals and more efficient serialization.
    private BigInteger priv;
    private byte[] pub;
    // Creation time of the key in seconds since the epoch, or zero if the key was deserialized from a version that did
    // not have this field.
    private long creationTimeSeconds;

    // Transient because it's calculated on demand.
    transient private byte[] pubKeyHash;

    /** Generates an entirely new keypair. */
    public ECKey() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(ecParams, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();
        priv = privParams.getD();
        // The public key is an encoded point on the elliptic curve. It has no meaning independent of the curve.
        pub = pubParams.getQ().getEncoded();
        creationTimeSeconds = Utils.now().getTime() / 1000;
    }

    /**
     * Construct an ECKey from an ASN.1 encoded private key. These are produced by OpenSSL and stored by the BitCoin
     * reference implementation in its wallet. Note that this is slow because it requires an EC point multiply.
     */
    public static ECKey fromASN1(byte[] asn1privkey) {
        return new ECKey(extractPrivateKeyFromASN1(asn1privkey));
    }

    /**
     * Output this ECKey as an ASN.1 encoded private key, as understood by OpenSSL or used by the BitCoin reference
     * implementation in its wallet storage format.
     */
    public byte[] toASN1() {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(400);

            // ASN1_SEQUENCE(EC_PRIVATEKEY) = {
            //   ASN1_SIMPLE(EC_PRIVATEKEY, version, LONG),
            //   ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
            //   ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
            //   ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
            // } ASN1_SEQUENCE_END(EC_PRIVATEKEY)
            DERSequenceGenerator seq = new DERSequenceGenerator(baos);
            seq.addObject(new ASN1Integer(1)); // version
            seq.addObject(new DEROctetString(priv.toByteArray()));
            seq.addObject(new DERTaggedObject(0, SECNamedCurves.getByName("secp256k1").toASN1Primitive()));
            seq.addObject(new DERTaggedObject(1, new DERBitString(getPubKey())));
            seq.close();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen, writing to memory stream.
        }
    }

    /**
     * Creates an ECKey given either the private key only, the public key only, or both. If only the private key 
     * is supplied, the public key will be calculated from it (this is slow). If both are supplied, it's assumed
     * the public key already correctly matches the public key. If only the public key is supplied, this ECKey cannot
     * be used for signing.
     */
    private ECKey(BigInteger privKey, byte[] pubKey) {
        this.priv = privKey;
        this.pub = null;
        if (pubKey == null && privKey != null) {
            // Derive public from private.
            this.pub = publicKeyFromPrivate(privKey);
        } else if (pubKey != null) {
            // We expect the pubkey to be in regular encoded form, just as a BigInteger. Therefore the first byte is
            // a special marker byte.
            // TODO: This is probably not a useful API and may be confusing.
            this.pub = pubKey;
        }
    }
    
    /** Creates an ECKey given the private key only.  The public key is calculated from it (this is slow) */
    public ECKey(BigInteger privKey) {
        this(privKey, (byte[])null);
    }
    
    /** A constructor variant with BigInteger pubkey. See {@link ECKey#ECKey(BigInteger, byte[])}. */
    public ECKey(BigInteger privKey, BigInteger pubKey) {
        this(privKey, Utils.bigIntegerToBytes(pubKey, 65));
    }

    /**
     * Creates an ECKey given only the private key bytes. This is the same as using the BigInteger constructor, but
     * is more convenient if you are importing a key from elsewhere. The public key will be automatically derived
     * from the private key.
     */
    public ECKey(byte[] privKeyBytes, byte[] pubKey) {
        this(privKeyBytes == null ? null : new BigInteger(1, privKeyBytes), pubKey);
    }

    /**
     * Returns public key bytes from the given private key. To convert a byte array into a BigInteger, use <tt>
     * new BigInteger(1, bytes);</tt>
     */
    public static byte[] publicKeyFromPrivate(BigInteger privKey) {
        return ecParams.getG().multiply(privKey).getEncoded();
    }

    /** Gets the hash160 form of the public key (as seen in addresses). */
    public byte[] getPubKeyHash() {
        if (pubKeyHash == null)
            pubKeyHash = Utils.sha256hash160(this.pub);
        return pubKeyHash;
    }

    /**
     * Gets the raw public key value. This appears in transaction scriptSigs. Note that this is <b>not</b> the same
     * as the pubKeyHash/address.
     */
    public byte[] getPubKey() {
        return pub;
    }

    public String toString() {
        StringBuffer b = new StringBuffer();
        b.append("pub:").append(Utils.bytesToHexString(pub));
        if (creationTimeSeconds != 0) {
            b.append(" timestamp:" + creationTimeSeconds);
        }
        return b.toString();
    }

    public String toStringWithPrivate() {
        StringBuffer b = new StringBuffer();
        b.append(toString());
        if (priv != null) {
            b.append(" priv:").append(Utils.bytesToHexString(priv.toByteArray()));
        }
        return b.toString();
    }

    /**
     * Returns the address that corresponds to the public part of this ECKey. Note that an address is derived from
     * the RIPEMD-160 hash of the public key and is not the public key itself (which is too large to be convenient).
     */
    public Address toAddress(NetworkParameters params) {
        byte[] hash160 = Utils.sha256hash160(pub);
        return new Address(params, hash160);
    }

    /**
     * Calcuates an ECDSA signature in DER format for the given input hash. Note that the input is expected to be
     * 32 bytes long.
     * @throws IllegalStateException if this ECKey has only a public key.
     */
    public byte[] sign(byte[] input) {
        if (priv == null)
            throw new IllegalStateException("This ECKey does not have the private key necessary for signing.");
        ECDSASigner signer = new ECDSASigner();
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(priv, ecParams);
        signer.init(true, privKey);
        BigInteger[] sigs = signer.generateSignature(input);
        // What we get back from the signer are the two components of a signature, r and s. To get a flat byte stream
        // of the type used by Bitcoin we have to encode them using DER encoding, which is just a way to pack the two
        // components into a structure.
        try {
            // Usually 70-72 bytes.
            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(72);
            DERSequenceGenerator seq = new DERSequenceGenerator(bos);
            seq.addObject(new DERInteger(sigs[0]));
            seq.addObject(new DERInteger(sigs[1]));
            seq.close();
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key.
     *
     * @param data      Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     * @param pub       The public key bytes to use.
     */
    public static boolean verify(byte[] data, byte[] signature, byte[] pub) {
        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params = new ECPublicKeyParameters(ecParams.getCurve().decodePoint(pub), ecParams);
        signer.init(false, params);
        try {
            ASN1InputStream decoder = new ASN1InputStream(signature);
            DLSequence seq = (DLSequence) decoder.readObject();
            DERInteger r = (DERInteger) seq.getObjectAt(0);
            DERInteger s = (DERInteger) seq.getObjectAt(1);
            decoder.close();
            return signer.verifySignature(data, r.getValue(), s.getValue());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key.
     *
     * @param data      Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     */
    public boolean verify(byte[] data, byte[] signature) {
        return ECKey.verify(data, signature, pub);
    }


    private static BigInteger extractPrivateKeyFromASN1(byte[] asn1privkey) {
        // To understand this code, see the definition of the ASN.1 format for EC private keys in the OpenSSL source
        // code in ec_asn1.c:
        //
        // ASN1_SEQUENCE(EC_PRIVATEKEY) = {
        //   ASN1_SIMPLE(EC_PRIVATEKEY, version, LONG),
        //   ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
        //   ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
        //   ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
        // } ASN1_SEQUENCE_END(EC_PRIVATEKEY)
        //
        try {
            ASN1InputStream decoder = new ASN1InputStream(asn1privkey);
            DLSequence seq = (DLSequence) decoder.readObject();
            checkArgument(seq.size() == 4, "Input does not appear to be an ASN.1 OpenSSL EC private key");
            checkArgument(((DERInteger) seq.getObjectAt(0)).getValue().equals(BigInteger.ONE),
                    "Input is of wrong version");
            Object obj = seq.getObjectAt(1);
            byte[] bits = ((ASN1OctetString) obj).getOctets();
            decoder.close();
            return new BigInteger(1, bits);
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen, reading from memory stream.
        }
    }

    /**
     * Returns a 32 byte array containing the private key.
     */
    public byte[] getPrivKeyBytes() {
        return Utils.bigIntegerToBytes(priv, 32);
    }
    
    /**
     * Exports the private key in the form used by the Satoshi client "dumpprivkey" and "importprivkey" commands. Use
     * the {@link com.google.bitcoin.core.DumpedPrivateKey#toString()} method to get the string.
     *
     * @param params The network this key is intended for use on.
     * @return Private key bytes as a {@link DumpedPrivateKey}.
     */
    public DumpedPrivateKey getPrivateKeyEncoded(NetworkParameters params) {
        return new DumpedPrivateKey(params, getPrivKeyBytes());
    }

    /**
     * Returns the creation time of this key or zero if the key was deserialized from a version that did not store
     * that data.
     */
    public long getCreationTimeSeconds() {
        return creationTimeSeconds;
    }

    /**
     * Sets the creation time of this key. Zero is a convention to mean "unavailable". This method can be useful when
     * you have a raw key you are importing from somewhere else.
     * @param newCreationTimeSeconds
     */
    public void setCreationTimeSeconds(long newCreationTimeSeconds) {
        if (newCreationTimeSeconds < 0)
            throw new IllegalArgumentException("Cannot set creation time to negative value: " + newCreationTimeSeconds);
        creationTimeSeconds = newCreationTimeSeconds;
    }
}
