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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import com.google.bitcoin.bouncycastle.asn1.ASN1InputStream;
import com.google.bitcoin.bouncycastle.asn1.ASN1OutputStream;
import com.google.bitcoin.bouncycastle.asn1.DERBitString;
import com.google.bitcoin.bouncycastle.asn1.DERInteger;
import com.google.bitcoin.bouncycastle.asn1.DEROctetString;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.DERSequenceGenerator;
import com.google.bitcoin.bouncycastle.asn1.DERTaggedObject;
import com.google.bitcoin.bouncycastle.asn1.sec.SECNamedCurves;
import com.google.bitcoin.bouncycastle.asn1.x9.X9ECParameters;
import com.google.bitcoin.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.google.bitcoin.bouncycastle.crypto.generators.ECKeyPairGenerator;
import com.google.bitcoin.bouncycastle.crypto.params.ECDomainParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ECKeyGenerationParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.google.bitcoin.bouncycastle.crypto.signers.ECDSASigner;

/**
 * Represents an elliptic curve keypair that we own and can use for signing transactions. Currently,
 * Bouncy Castle is used. In future this may become an interface with multiple implementations using different crypto
 * libraries. The class also provides a static method that can verify a signature with just the public key.<p>
 */
public class ECKey implements Serializable {
    private static final ECDomainParameters ecParams;

    private static final SecureRandom secureRandom;
    private static final long serialVersionUID = -728224901792295832L;

    static {
        // All clients must agree on the curve to use by agreement. BitCoin uses secp256k1.
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(),  params.getH());
        secureRandom = new SecureRandom();
    }

    private final BigInteger priv;
    private final byte[] pub;
    
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
    }

    /**
     * Construct an ECKey from an ASN.1 encoded private key. These are produced by OpenSSL and stored by the BitCoin
     * reference implementation in its wallet.
     */
    public static ECKey fromASN1(byte[] asn1privkey) {
        return new ECKey(extractPrivateKeyFromASN1(asn1privkey));
    }

    /**
     * Output this ECKey as an ASN.1 encoded private key, as understood by OpenSSL or used by the BitCoin reference
     * implementation in its wallet storage format.
     */
    public byte[] toASN1(){
         try {
             ByteArrayOutputStream baos = new ByteArrayOutputStream(400);
             ASN1OutputStream encoder = new ASN1OutputStream(baos);

             // ASN1_SEQUENCE(EC_PRIVATEKEY) = {
             //   ASN1_SIMPLE(EC_PRIVATEKEY, version, LONG),
             //   ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
             //   ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
             //   ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
             // } ASN1_SEQUENCE_END(EC_PRIVATEKEY)
             DERSequenceGenerator seq = new DERSequenceGenerator(encoder);
             seq.addObject(new DERInteger(1)); // version
             seq.addObject(new DEROctetString(priv.toByteArray()));
             seq.addObject(new DERTaggedObject(0, SECNamedCurves.getByName("secp256k1").getDERObject()));
             seq.addObject(new DERTaggedObject(1, new DERBitString(getPubKey())));
             seq.close();
             encoder.close();
             return baos.toByteArray();
         } catch (IOException e) {
             throw new RuntimeException(e);  // Cannot happen, writing to memory stream.
         }
    }

    /**
     * Creates an ECKey given only the private key. This works because EC public keys are derivable from their
     * private keys by doing a multiply with the generator value.
     */
    public ECKey(BigInteger privKey) {
        this.priv = privKey;
        this.pub = publicKeyFromPrivate(privKey);
    }

    /** Derive the public key by doing a point multiply of G * priv. */
    private static byte[] publicKeyFromPrivate(BigInteger privKey) {
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
        b.append(" priv:").append(Utils.bytesToHexString(priv.toByteArray()));
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
     */
    public byte[] sign(byte[] input) {
        ECDSASigner signer = new ECDSASigner();
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(priv, ecParams);
        signer.init(true, privKey);
        BigInteger[] sigs = signer.generateSignature(input);
        // What we get back from the signer are the two components of a signature, r and s. To get a flat byte stream
        // of the type used by BitCoin we have to encode them using DER encoding, which is just a way to pack the two
        // components into a structure.
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
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
     * @param data Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     * @param pub The public key bytes to use.
     */
    public static boolean verify(byte[] data, byte[] signature, byte[] pub) {
        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params = new ECPublicKeyParameters(ecParams.getCurve().decodePoint(pub), ecParams);
        signer.init(false, params);
        try {
            ASN1InputStream decoder = new ASN1InputStream(signature);
            DERSequence seq = (DERSequence) decoder.readObject();
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
     * @param data Hash of the data to verify.
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
            DERSequence seq = (DERSequence) decoder.readObject();
            assert seq.size() == 4 : "Input does not appear to be an ASN.1 OpenSSL EC private key";
            assert ((DERInteger) seq.getObjectAt(0)).getValue().equals(BigInteger.ONE) : "Input is of wrong version";
            DEROctetString key = (DEROctetString) seq.getObjectAt(1);
            decoder.close();
            return new BigInteger(key.getOctets());
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen, reading from memory stream.
        }
    }
}
