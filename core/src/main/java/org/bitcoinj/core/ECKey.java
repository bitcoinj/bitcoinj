/**
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoinj.core;

import org.bitcoinj.crypto.*;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Objects;
import com.google.common.base.Objects.ToStringHelper;
import com.google.common.base.Preconditions;
import com.google.common.primitives.UnsignedBytes;
import org.bitcoin.NativeSecp256k1;
import org.bitcoinj.wallet.Protos;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.asn1.*;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.asn1.x9.X9IntegerConverter;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.ec.CustomNamedCurves;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.*;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.crypto.signers.HMacDSAKCalculator;
import org.spongycastle.math.ec.ECAlgorithms;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.FixedPointUtil;
import org.spongycastle.math.ec.custom.sec.SecP256K1Curve;
import org.spongycastle.util.encoders.Base64;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Comparator;

import static com.google.common.base.Preconditions.*;

// TODO: Move this class to tracking compression state itself.
// The Bouncy Castle guys are deprecating their own tracking of the compression state.

/**
 * <p>Represents an elliptic curve public and (optionally) private key, usable for digital signatures but not encryption.
 * Creating a new ECKey with the empty constructor will generate a new random keypair. Other static methods can be used
 * when you already have the public or private parts. If you create a key with only the public part, you can check
 * signatures but not create them.</p>
 *
 * <p>ECKey also provides access to Bitcoin Core compatible text message signing, as accessible via the UI or JSON-RPC.
 * This is slightly different to signing raw bytes - if you want to sign your own data and it won't be exposed as
 * text to people, you don't want to use this. If in doubt, ask on the mailing list.</p>
 *
 * <p>The ECDSA algorithm supports <i>key recovery</i> in which a signature plus a couple of discriminator bits can
 * be reversed to find the public key used to calculate it. This can be convenient when you have a message and a
 * signature and want to find out who signed it, rather than requiring the user to provide the expected identity.</p>
 *
 * <p>This class supports a variety of serialization forms. The methods that accept/return byte arrays serialize
 * private keys as raw byte arrays and public keys using the SEC standard byte encoding for public keys. Signatures
 * are encoded using ASN.1/DER inside the Bitcoin protocol.</p>
 *
 * <p>A key can be <i>compressed</i> or <i>uncompressed</i>. This refers to whether the public key is represented
 * when encoded into bytes as an (x, y) coordinate on the elliptic curve, or whether it's represented as just an X
 * co-ordinate and an extra byte that carries a sign bit. With the latter form the Y coordinate can be calculated
 * dynamically, however, <b>because the binary serialization is different the address of a key changes if its
 * compression status is changed</b>. If you deviate from the defaults it's important to understand this: money sent
 * to a compressed version of the key will have a different address to the same key in uncompressed form. Whether
 * a public key is compressed or not is recorded in the SEC binary serialisation format, and preserved in a flag in
 * this class so round-tripping preserves state. Unless you're working with old software or doing unusual things, you
 * can usually ignore the compressed/uncompressed distinction.</p>
 */
public class ECKey implements EncryptableItem, Serializable {
    private static final Logger log = LoggerFactory.getLogger(ECKey.class);

    /** Sorts oldest keys first, newest last. */
    public static final Comparator<ECKey> AGE_COMPARATOR = new Comparator<ECKey>() {

        @Override
        public int compare(ECKey k1, ECKey k2) {
            if (k1.creationTimeSeconds == k2.creationTimeSeconds)
                return 0;
            else
                return k1.creationTimeSeconds > k2.creationTimeSeconds ? 1 : -1;
        }
    };

    /** Compares pub key bytes using {@link com.google.common.primitives.UnsignedBytes#lexicographicalComparator()} */
    public static final Comparator<ECKey> PUBKEY_COMPARATOR = new Comparator<ECKey>() {
        private Comparator<byte[]> comparator = UnsignedBytes.lexicographicalComparator();

        @Override
        public int compare(ECKey k1, ECKey k2) {
            return comparator.compare(k1.getPubKey(), k2.getPubKey());
        }
    };

    /** The parameters of the secp256k1 curve that Bitcoin uses. */
    public static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");

    /** The parameters of the secp256k1 curve that Bitcoin uses. */
    public static final ECDomainParameters CURVE;

    /**
     * Equal to CURVE.getN().shiftRight(1), used for canonicalising the S value of a signature. If you aren't
     * sure what this is about, you can ignore it.
     */
    public static final BigInteger HALF_CURVE_ORDER;

    private static final SecureRandom secureRandom;
    private static final long serialVersionUID = -728224901792295832L;

    static {
        // Tell Bouncy Castle to precompute data that's needed during secp256k1 calculations. Increasing the width
        // number makes calculations faster, but at a cost of extra memory usage and with decreasing returns. 12 was
        // picked after consulting with the BC team.
        FixedPointUtil.precompute(CURVE_PARAMS.getG(), 12);
        CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(),
                CURVE_PARAMS.getH());
        HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);
        secureRandom = new SecureRandom();
    }

    // The two parts of the key. If "priv" is set, "pub" can always be calculated. If "pub" is set but not "priv", we
    // can only verify signatures not make them.
    protected final BigInteger priv;  // A field element.
    protected final LazyECPoint pub;

    // Creation time of the key in seconds since the epoch, or zero if the key was deserialized from a version that did
    // not have this field.
    protected long creationTimeSeconds;

    protected KeyCrypter keyCrypter;
    protected EncryptedData encryptedPrivateKey;

    // Transient because it's calculated on demand/cached.
    private transient byte[] pubKeyHash;

    /**
     * Generates an entirely new keypair. Point compression is used so the resulting public key will be 33 bytes
     * (32 for the co-ordinate and 1 byte to represent the y bit).
     */
    public ECKey() {
        this(secureRandom);
    }

    /**
     * Generates an entirely new keypair with the given {@link SecureRandom} object. Point compression is used so the
     * resulting public key will be 33 bytes (32 for the co-ordinate and 1 byte to represent the y bit).
     */
    public ECKey(SecureRandom secureRandom) {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(CURVE, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();
        priv = privParams.getD();
        pub = new LazyECPoint(CURVE.getCurve(), pubParams.getQ().getEncoded(true));
        creationTimeSeconds = Utils.currentTimeSeconds();
    }

    protected ECKey(@Nullable BigInteger priv, ECPoint pub) {
        if (priv != null) {
            // Try and catch buggy callers or bad key imports, etc. Zero and one are special because these are often
            // used as sentinel values and because scripting languages have a habit of auto-casting true and false to
            // 1 and 0 or vice-versa. Type confusion bugs could therefore result in private keys with these values.
            checkArgument(!priv.equals(BigInteger.ZERO));
            checkArgument(!priv.equals(BigInteger.ONE));
        }
        this.priv = priv;
        this.pub = new LazyECPoint(checkNotNull(pub));
    }

    protected ECKey(@Nullable BigInteger priv, LazyECPoint pub) {
        this.priv = priv;
        this.pub = checkNotNull(pub);
    }

    /**
     * Utility for compressing an elliptic curve point. Returns the same point if it's already compressed.
     * See the ECKey class docs for a discussion of point compression.
     */
    public static ECPoint compressPoint(ECPoint point) {
        return point.isCompressed() ? point : CURVE.getCurve().decodePoint(point.getEncoded(true));
    }

    public static LazyECPoint compressPoint(LazyECPoint point) {
        return point.isCompressed() ? point : new LazyECPoint(compressPoint(point.get()));
    }

    /**
     * Utility for decompressing an elliptic curve point. Returns the same point if it's already compressed.
     * See the ECKey class docs for a discussion of point compression.
     */
    public static ECPoint decompressPoint(ECPoint point) {
        return !point.isCompressed() ? point : CURVE.getCurve().decodePoint(point.getEncoded(false));
    }

    public static LazyECPoint decompressPoint(LazyECPoint point) {
        return !point.isCompressed() ? point : new LazyECPoint(decompressPoint(point.get()));
    }

    /**
     * Construct an ECKey from an ASN.1 encoded private key. These are produced by OpenSSL and stored by the Bitcoin
     * reference implementation in its wallet. Note that this is slow because it requires an EC point multiply.
     */
    public static ECKey fromASN1(byte[] asn1privkey) {
        return extractKeyFromASN1(asn1privkey);
    }

    /**
     * Creates an ECKey given the private key only. The public key is calculated from it (this is slow). The resulting
     * public key is compressed.
     */
    public static ECKey fromPrivate(BigInteger privKey) {
        return fromPrivate(privKey, true);
    }

    /**
     * Creates an ECKey given the private key only. The public key is calculated from it (this is slow), either
     * compressed or not.
     */
    public static ECKey fromPrivate(BigInteger privKey, boolean compressed) {
        ECPoint point = CURVE.getG().multiply(privKey);
        return new ECKey(privKey, compressed ? compressPoint(point) : decompressPoint(point));
    }

    /**
     * Creates an ECKey given the private key only. The public key is calculated from it (this is slow). The resulting
     * public key is compressed.
     */
    public static ECKey fromPrivate(byte[] privKeyBytes) {
        return fromPrivate(new BigInteger(1, privKeyBytes));
    }

    /**
     * Creates an ECKey given the private key only. The public key is calculated from it (this is slow), either
     * compressed or not.
     */
    public static ECKey fromPrivate(byte[] privKeyBytes, boolean compressed) {
        return fromPrivate(new BigInteger(1, privKeyBytes), compressed);
    }

    /**
     * Creates an ECKey that simply trusts the caller to ensure that point is really the result of multiplying the
     * generator point by the private key. This is used to speed things up when you know you have the right values
     * already. The compression state of pub will be preserved.
     */
    public static ECKey fromPrivateAndPrecalculatedPublic(BigInteger priv, ECPoint pub) {
        return new ECKey(priv, pub);
    }

    /**
     * Creates an ECKey that simply trusts the caller to ensure that point is really the result of multiplying the
     * generator point by the private key. This is used to speed things up when you know you have the right values
     * already. The compression state of the point will be preserved.
     */
    public static ECKey fromPrivateAndPrecalculatedPublic(byte[] priv, byte[] pub) {
        checkNotNull(priv);
        checkNotNull(pub);
        return new ECKey(new BigInteger(1, priv), CURVE.getCurve().decodePoint(pub));
    }

    /**
     * Creates an ECKey that cannot be used for signing, only verifying signatures, from the given point. The
     * compression state of pub will be preserved.
     */
    public static ECKey fromPublicOnly(ECPoint pub) {
        return new ECKey(null, pub);
    }

    /**
     * Creates an ECKey that cannot be used for signing, only verifying signatures, from the given encoded point.
     * The compression state of pub will be preserved.
     */
    public static ECKey fromPublicOnly(byte[] pub) {
        return new ECKey(null, CURVE.getCurve().decodePoint(pub));
    }

    /**
     * Returns a copy of this key, but with the public point represented in uncompressed form. Normally you would
     * never need this: it's for specialised scenarios or when backwards compatibility in encoded form is necessary.
     */
    public ECKey decompress() {
        if (!pub.isCompressed())
            return this;
        else
            return new ECKey(priv, decompressPoint(pub.get()));
    }

    /**
     * Creates an ECKey given only the private key bytes. This is the same as using the BigInteger constructor, but
     * is more convenient if you are importing a key from elsewhere. The public key will be automatically derived
     * from the private key.
     */
    @Deprecated
    public ECKey(@Nullable byte[] privKeyBytes, @Nullable byte[] pubKey) {
        this(privKeyBytes == null ? null : new BigInteger(1, privKeyBytes), pubKey);
    }

    /**
     * Create a new ECKey with an encrypted private key, a public key and a KeyCrypter.
     *
     * @param encryptedPrivateKey The private key, encrypted,
     * @param pubKey The keys public key
     * @param keyCrypter The KeyCrypter that will be used, with an AES key, to encrypt and decrypt the private key
     */
    @Deprecated
    public ECKey(EncryptedData encryptedPrivateKey, byte[] pubKey, KeyCrypter keyCrypter) {
        this((byte[])null, pubKey);

        this.keyCrypter = checkNotNull(keyCrypter);
        this.encryptedPrivateKey = encryptedPrivateKey;
    }

    /**
     * Constructs a key that has an encrypted private component. The given object wraps encrypted bytes and an
     * initialization vector. Note that the key will not be decrypted during this call: the returned ECKey is
     * unusable for signing unless a decryption key is supplied.
     */
    public static ECKey fromEncrypted(EncryptedData encryptedPrivateKey, KeyCrypter crypter, byte[] pubKey) {
        ECKey key = fromPublicOnly(pubKey);
        key.encryptedPrivateKey = checkNotNull(encryptedPrivateKey);
        key.keyCrypter = checkNotNull(crypter);
        return key;
    }

    /**
     * Creates an ECKey given either the private key only, the public key only, or both. If only the private key
     * is supplied, the public key will be calculated from it (this is slow). If both are supplied, it's assumed
     * the public key already correctly matches the public key. If only the public key is supplied, this ECKey cannot
     * be used for signing.
     * @param compressed If set to true and pubKey is null, the derived public key will be in compressed form.
     */
    @Deprecated
    public ECKey(@Nullable BigInteger privKey, @Nullable byte[] pubKey, boolean compressed) {
        if (privKey == null && pubKey == null)
            throw new IllegalArgumentException("ECKey requires at least private or public key");
        this.priv = privKey;
        if (pubKey == null) {
            // Derive public from private.
            ECPoint point = CURVE.getG().multiply(privKey);
            if (compressed)
                point = compressPoint(point);
            this.pub = new LazyECPoint(point);
        } else {
            // We expect the pubkey to be in regular encoded form, just as a BigInteger. Therefore the first byte is
            // a special marker byte.
            // TODO: This is probably not a useful API and may be confusing.
            this.pub = new LazyECPoint(CURVE.getCurve(), pubKey);
        }
    }

    /**
     * Creates an ECKey given either the private key only, the public key only, or both. If only the private key
     * is supplied, the public key will be calculated from it (this is slow). If both are supplied, it's assumed
     * the public key already correctly matches the public key. If only the public key is supplied, this ECKey cannot
     * be used for signing.
     */
    @Deprecated
    private ECKey(@Nullable BigInteger privKey, @Nullable byte[] pubKey) {
        this(privKey, pubKey, false);
    }

    /**
     * Returns true if this key doesn't have unencrypted access to private key bytes. This may be because it was never
     * given any private key bytes to begin with (a watching key), or because the key is encrypted. You can use
     * {@link #isEncrypted()} to tell the cases apart.
     */
    public boolean isPubKeyOnly() {
        return priv == null;
    }

    /**
     * Returns true if this key has unencrypted access to private key bytes. Does the opposite of
     * {@link #isPubKeyOnly()}.
     */
    public boolean hasPrivKey() {
        return priv != null;
    }

    /**
     * Output this ECKey as an ASN.1 encoded private key, as understood by OpenSSL or used by the Bitcoin reference
     * implementation in its wallet storage format.
     * @throws org.bitcoinj.core.ECKey.MissingPrivateKeyException if the private key is missing or encrypted.
     */
    public byte[] toASN1() {
        try {
            byte[] privKeyBytes = getPrivKeyBytes();
            ByteArrayOutputStream baos = new ByteArrayOutputStream(400);

            // ASN1_SEQUENCE(EC_PRIVATEKEY) = {
            //   ASN1_SIMPLE(EC_PRIVATEKEY, version, LONG),
            //   ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
            //   ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
            //   ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
            // } ASN1_SEQUENCE_END(EC_PRIVATEKEY)
            DERSequenceGenerator seq = new DERSequenceGenerator(baos);
            seq.addObject(new ASN1Integer(1)); // version
            seq.addObject(new DEROctetString(privKeyBytes));
            seq.addObject(new DERTaggedObject(0, CURVE_PARAMS.toASN1Primitive()));
            seq.addObject(new DERTaggedObject(1, new DERBitString(getPubKey())));
            seq.close();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen, writing to memory stream.
        }
    }

    /**
     * Returns public key bytes from the given private key. To convert a byte array into a BigInteger, use <tt>
     * new BigInteger(1, bytes);</tt>
     */
    public static byte[] publicKeyFromPrivate(BigInteger privKey, boolean compressed) {
        ECPoint point = CURVE.getG().multiply(privKey);
        return point.getEncoded(compressed);
    }

    /** Gets the hash160 form of the public key (as seen in addresses). */
    public byte[] getPubKeyHash() {
        if (pubKeyHash == null)
            pubKeyHash = Utils.sha256hash160(this.pub.getEncoded());
        return pubKeyHash;
    }

    /**
     * Gets the raw public key value. This appears in transaction scriptSigs. Note that this is <b>not</b> the same
     * as the pubKeyHash/address.
     */
    public byte[] getPubKey() {
        return pub.getEncoded();
    }

    /** Gets the public key in the form of an elliptic curve point object from Bouncy Castle. */
    public ECPoint getPubKeyPoint() {
        return pub.get();
    }

    /**
     * Gets the private key in the form of an integer field element. The public key is derived by performing EC
     * point addition this number of times (i.e. point multiplying).
     *
     * @throws java.lang.IllegalStateException if the private key bytes are not available.
     */
    public BigInteger getPrivKey() {
        if (priv == null)
            throw new MissingPrivateKeyException();
        return priv;
    }

    /**
     * Returns whether this key is using the compressed form or not. Compressed pubkeys are only 33 bytes, not 64.
     */
    public boolean isCompressed() {
        return pub.isCompressed();
    }

    /**
     * Returns the address that corresponds to the public part of this ECKey. Note that an address is derived from
     * the RIPEMD-160 hash of the public key and is not the public key itself (which is too large to be convenient).
     */
    public Address toAddress(NetworkParameters params) {
        return new Address(params, getPubKeyHash());
    }

    /**
     * Groups the two components that make up a signature, and provides a way to encode to DER form, which is
     * how ECDSA signatures are represented when embedded in other data structures in the Bitcoin protocol. The raw
     * components can be useful for doing further EC maths on them.
     */
    public static class ECDSASignature {
        /** The two components of the signature. */
        public final BigInteger r, s;

        /**
         * Constructs a signature with the given components. Does NOT automatically canonicalise the signature.
         */
        public ECDSASignature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }

        /**
         * Will automatically adjust the S component to be less than or equal to half the curve order, if necessary.
         * This is required because for every signature (r,s) the signature (r, -s (mod N)) is a valid signature of
         * the same message. However, we dislike the ability to modify the bits of a Bitcoin transaction after it's
         * been signed, as that violates various assumed invariants. Thus in future only one of those forms will be
         * considered legal and the other will be banned.
         */
        public ECDSASignature toCanonicalised() {
            if (s.compareTo(HALF_CURVE_ORDER) > 0) {
                // The order of the curve is the number of valid points that exist on that curve. If S is in the upper
                // half of the number of valid points, then bring it back to the lower half. Otherwise, imagine that
                //    N = 10
                //    s = 8, so (-8 % 10 == 2) thus both (r, 8) and (r, 2) are valid solutions.
                //    10 - 8 == 2, giving us always the latter solution, which is canonical.
                return new ECDSASignature(r, CURVE.getN().subtract(s));
            } else {
                return this;
            }
        }

        /**
         * DER is an international standard for serializing data structures which is widely used in cryptography.
         * It's somewhat like protocol buffers but less convenient. This method returns a standard DER encoding
         * of the signature, as recognized by OpenSSL and other libraries.
         */
        public byte[] encodeToDER() {
            try {
                return derByteStream().toByteArray();
            } catch (IOException e) {
                throw new RuntimeException(e);  // Cannot happen.
            }
        }

        public static ECDSASignature decodeFromDER(byte[] bytes) {
            ASN1InputStream decoder = null;
            try {
                decoder = new ASN1InputStream(bytes);
                DLSequence seq = (DLSequence) decoder.readObject();
                if (seq == null)
                    throw new RuntimeException("Reached past end of ASN.1 stream.");
                ASN1Integer r, s;
                try {
                    r = (ASN1Integer) seq.getObjectAt(0);
                    s = (ASN1Integer) seq.getObjectAt(1);
                } catch (ClassCastException e) {
                    throw new IllegalArgumentException(e);
                }
                // OpenSSL deviates from the DER spec by interpreting these values as unsigned, though they should not be
                // Thus, we always use the positive versions. See: http://r6.ca/blog/20111119T211504Z.html
                return new ECDSASignature(r.getPositiveValue(), s.getPositiveValue());
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                if (decoder != null)
                    try { decoder.close(); } catch (IOException x) {}
            }
        }

        protected ByteArrayOutputStream derByteStream() throws IOException {
            // Usually 70-72 bytes.
            ByteArrayOutputStream bos = new ByteArrayOutputStream(72);
            DERSequenceGenerator seq = new DERSequenceGenerator(bos);
            seq.addObject(new ASN1Integer(r));
            seq.addObject(new ASN1Integer(s));
            seq.close();
            return bos;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ECDSASignature other = (ECDSASignature) o;
            return r.equals(other.r) &&
                   s.equals(other.s);
        }

        @Override
        public int hashCode() {
            int result = r.hashCode();
            result = 31 * result + s.hashCode();
            return result;
        }
    }

    /**
     * Signs the given hash and returns the R and S components as BigIntegers. In the Bitcoin protocol, they are
     * usually encoded using ASN.1 format, so you want {@link org.bitcoinj.core.ECKey.ECDSASignature#toASN1()}
     * instead. However sometimes the independent components can be useful, for instance, if you're going to do
     * further EC maths on them.
     * @throws KeyCrypterException if this ECKey doesn't have a private part.
     */
    public ECDSASignature sign(Sha256Hash input) throws KeyCrypterException {
        return sign(input, null);
    }

    /**
     * If this global variable is set to true, sign() creates a dummy signature and verify() always returns true.
     * This is intended to help accelerate unit tests that do a lot of signing/verifying, which in the debugger
     * can be painfully slow.
     */
    @VisibleForTesting
    public static boolean FAKE_SIGNATURES = false;

    /**
     * Signs the given hash and returns the R and S components as BigIntegers. In the Bitcoin protocol, they are
     * usually encoded using DER format, so you want {@link org.bitcoinj.core.ECKey.ECDSASignature#encodeToDER()}
     * instead. However sometimes the independent components can be useful, for instance, if you're doing to do further
     * EC maths on them.
     *
     * @param aesKey The AES key to use for decryption of the private key. If null then no decryption is required.
     * @throws KeyCrypterException if there's something wrong with aesKey.
     * @throws ECKey.MissingPrivateKeyException if this key cannot sign because it's pubkey only.
     */
    public ECDSASignature sign(Sha256Hash input, @Nullable KeyParameter aesKey) throws KeyCrypterException {
        KeyCrypter crypter = getKeyCrypter();
        if (crypter != null) {
            if (aesKey == null)
                throw new KeyIsEncryptedException();
            return decrypt(aesKey).sign(input);
        } else {
            // No decryption of private key required.
            if (priv == null)
                throw new MissingPrivateKeyException();
        }
        return doSign(input, priv);
    }

    protected ECDSASignature doSign(Sha256Hash input, BigInteger privateKeyForSigning) {
        if (FAKE_SIGNATURES)
            return TransactionSignature.dummy();
        checkNotNull(privateKeyForSigning);
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKeyForSigning, CURVE);
        signer.init(true, privKey);
        BigInteger[] components = signer.generateSignature(input.getBytes());
        return new ECDSASignature(components[0], components[1]).toCanonicalised();
    }

    /**
     * <p>Verifies the given ECDSA signature against the message bytes using the public key bytes.</p>
     * 
     * <p>When using native ECDSA verification, data must be 32 bytes, and no element may be
     * larger than 520 bytes.</p>
     *
     * @param data      Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     * @param pub       The public key bytes to use.
     */
    public static boolean verify(byte[] data, ECDSASignature signature, byte[] pub) {
        if (FAKE_SIGNATURES)
            return true;

        if (NativeSecp256k1.enabled)
            return NativeSecp256k1.verify(data, signature.encodeToDER(), pub);

        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params = new ECPublicKeyParameters(CURVE.getCurve().decodePoint(pub), CURVE);
        signer.init(false, params);
        try {
            return signer.verifySignature(data, signature.r, signature.s);
        } catch (NullPointerException e) {
            // Bouncy Castle contains a bug that can cause NPEs given specially crafted signatures. Those signatures
            // are inherently invalid/attack sigs so we just fail them here rather than crash the thread.
            log.error("Caught NPE inside bouncy castle");
            e.printStackTrace();
            return false;
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
        if (NativeSecp256k1.enabled)
            return NativeSecp256k1.verify(data, signature, pub);
        return verify(data, ECDSASignature.decodeFromDER(signature), pub);
    }

    /**
     * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key.
     *
     * @param data      Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     */
    public boolean verify(byte[] data, byte[] signature) {
        return ECKey.verify(data, signature, getPubKey());
    }

    /**
     * Verifies the given R/S pair (signature) against a hash using the public key.
     */
    public boolean verify(Sha256Hash sigHash, ECDSASignature signature) {
        return ECKey.verify(sigHash.getBytes(), signature, getPubKey());
    }

    /**
     * Returns true if the given pubkey is canonical, i.e. the correct length taking into account compression.
     */
    public static boolean isPubKeyCanonical(byte[] pubkey) {
        if (pubkey.length < 33)
            return false;
        if (pubkey[0] == 0x04) {
            // Uncompressed pubkey
            if (pubkey.length != 65)
                return false;
        } else if (pubkey[0] == 0x02 || pubkey[0] == 0x03) {
            // Compressed pubkey
            if (pubkey.length != 33)
                return false;
        } else
            return false;
        return true;
    }

    private static ECKey extractKeyFromASN1(byte[] asn1privkey) {
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
            checkArgument(((ASN1Integer) seq.getObjectAt(0)).getValue().equals(BigInteger.ONE),
                    "Input is of wrong version");
            Object obj = seq.getObjectAt(1);
            byte[] privbits = ((ASN1OctetString) obj).getOctets();
            decoder.close();
            BigInteger privkey = new BigInteger(1, privbits);
            byte[] pubbits = ((DERBitString)((ASN1TaggedObject)seq.getObjectAt(3)).getObject()).getBytes();
            // Now sanity check to ensure the pubkey bytes match the privkey.
            byte[] compressed = publicKeyFromPrivate(privkey, true);
            if (Arrays.equals(pubbits, compressed))
                return new ECKey(privkey, compressed);
            byte[] uncompressed = publicKeyFromPrivate(privkey, false);
            if (Arrays.equals(pubbits, uncompressed))
                return new ECKey(privkey, uncompressed);
            throw new IllegalArgumentException("Public key in ASN.1 structure does not match private key.");
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen, reading from memory stream.
        }
    }

    /**
     * Signs a text message using the standard Bitcoin messaging signing format and returns the signature as a base64
     * encoded string.
     *
     * @throws IllegalStateException if this ECKey does not have the private part.
     * @throws KeyCrypterException if this ECKey is encrypted and no AESKey is provided or it does not decrypt the ECKey.
     */
    public String signMessage(String message) throws KeyCrypterException {
        return signMessage(message, null);
    }

    /**
     * Signs a text message using the standard Bitcoin messaging signing format and returns the signature as a base64
     * encoded string.
     *
     * @throws IllegalStateException if this ECKey does not have the private part.
     * @throws KeyCrypterException if this ECKey is encrypted and no AESKey is provided or it does not decrypt the ECKey.
     */
    public String signMessage(String message, @Nullable KeyParameter aesKey) throws KeyCrypterException {
        byte[] data = Utils.formatMessageForSigning(message);
        Sha256Hash hash = Sha256Hash.createDouble(data);
        ECDSASignature sig = sign(hash, aesKey);
        // Now we have to work backwards to figure out the recId needed to recover the signature.
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            ECKey k = ECKey.recoverFromSignature(i, sig, hash, isCompressed());
            if (k != null && k.pub.equals(pub)) {
                recId = i;
                break;
            }
        }
        if (recId == -1)
            throw new RuntimeException("Could not construct a recoverable key. This should never happen.");
        int headerByte = recId + 27 + (isCompressed() ? 4 : 0);
        byte[] sigData = new byte[65];  // 1 header + 32 bytes for R + 32 bytes for S
        sigData[0] = (byte)headerByte;
        System.arraycopy(Utils.bigIntegerToBytes(sig.r, 32), 0, sigData, 1, 32);
        System.arraycopy(Utils.bigIntegerToBytes(sig.s, 32), 0, sigData, 33, 32);
        return new String(Base64.encode(sigData), Charset.forName("UTF-8"));
    }

    /**
     * Given an arbitrary piece of text and a Bitcoin-format message signature encoded in base64, returns an ECKey
     * containing the public key that was used to sign it. This can then be compared to the expected public key to
     * determine if the signature was correct. These sorts of signatures are compatible with the Bitcoin-Qt/bitcoind
     * format generated by signmessage/verifymessage RPCs and GUI menu options. They are intended for humans to verify
     * their communications with each other, hence the base64 format and the fact that the input is text.
     *
     * @param message Some piece of human readable text.
     * @param signatureBase64 The Bitcoin-format message signature in base64
     * @throws SignatureException If the public key could not be recovered or if there was a signature format error.
     */
    public static ECKey signedMessageToKey(String message, String signatureBase64) throws SignatureException {
        byte[] signatureEncoded;
        try {
            signatureEncoded = Base64.decode(signatureBase64);
        } catch (RuntimeException e) {
            // This is what you get back from Bouncy Castle if base64 doesn't decode :(
            throw new SignatureException("Could not decode base64", e);
        }
        // Parse the signature bytes into r/s and the selector value.
        if (signatureEncoded.length < 65)
            throw new SignatureException("Signature truncated, expected 65 bytes and got " + signatureEncoded.length);
        int header = signatureEncoded[0] & 0xFF;
        // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
        //                  0x1D = second key with even y, 0x1E = second key with odd y
        if (header < 27 || header > 34)
            throw new SignatureException("Header byte out of range: " + header);
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signatureEncoded, 1, 33));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signatureEncoded, 33, 65));
        ECDSASignature sig = new ECDSASignature(r, s);
        byte[] messageBytes = Utils.formatMessageForSigning(message);
        // Note that the C++ code doesn't actually seem to specify any character encoding. Presumably it's whatever
        // JSON-SPIRIT hands back. Assume UTF-8 for now.
        Sha256Hash messageHash = Sha256Hash.createDouble(messageBytes);
        boolean compressed = false;
        if (header >= 31) {
            compressed = true;
            header -= 4;
        }
        int recId = header - 27;
        ECKey key = ECKey.recoverFromSignature(recId, sig, messageHash, compressed);
        if (key == null)
            throw new SignatureException("Could not recover public key from signature");
        return key;
    }

    /**
     * Convenience wrapper around {@link ECKey#signedMessageToKey(String, String)}. If the key derived from the
     * signature is not the same as this one, throws a SignatureException.
     */
    public void verifyMessage(String message, String signatureBase64) throws SignatureException {
        ECKey key = ECKey.signedMessageToKey(message, signatureBase64);
        if (!key.pub.equals(pub))
            throw new SignatureException("Signature did not match for message");
    }

    /**
     * <p>Given the components of a signature and a selector value, recover and return the public key
     * that generated the signature according to the algorithm in SEC1v2 section 4.1.6.</p>
     *
     * <p>The recId is an index from 0 to 3 which indicates which of the 4 possible keys is the correct one. Because
     * the key recovery operation yields multiple potential keys, the correct key must either be stored alongside the
     * signature, or you must be willing to try each recId in turn until you find one that outputs the key you are
     * expecting.</p>
     *
     * <p>If this method returns null it means recovery was not possible and recId should be iterated.</p>
     *
     * <p>Given the above two points, a correct usage of this method is inside a for loop from 0 to 3, and if the
     * output is null OR a key that is not the one you expect, you try again with the next recId.</p>
     *
     * @param recId Which possible key to recover.
     * @param sig the R and S components of the signature, wrapped.
     * @param message Hash of the data that was signed.
     * @param compressed Whether or not the original pubkey was compressed.
     * @return An ECKey containing only the public part, or null if recovery wasn't possible.
     */
    @Nullable
    public static ECKey recoverFromSignature(int recId, ECDSASignature sig, Sha256Hash message, boolean compressed) {
        Preconditions.checkArgument(recId >= 0, "recId must be positive");
        Preconditions.checkArgument(sig.r.signum() >= 0, "r must be positive");
        Preconditions.checkArgument(sig.s.signum() >= 0, "s must be positive");
        Preconditions.checkNotNull(message);
        // 1.0 For j from 0 to h   (h == recId here and the loop is outside this function)
        //   1.1 Let x = r + jn
        BigInteger n = CURVE.getN();  // Curve order.
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = sig.r.add(i.multiply(n));
        //   1.2. Convert the integer x to an octet string X of length mlen using the conversion routine
        //        specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen = ⌈m/8⌉.
        //   1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R using the
        //        conversion routine specified in Section 2.3.4. If this conversion routine outputs “invalid”, then
        //        do another iteration of Step 1.
        //
        // More concisely, what these points mean is to use X as a compressed public key.
        BigInteger prime = SecP256K1Curve.q;
        if (x.compareTo(prime) >= 0) {
            // Cannot have point co-ordinates larger than this as everything takes place modulo Q.
            return null;
        }
        // Compressed keys require you to know an extra bit of data about the y-coord as there are two possibilities.
        // So it's encoded in the recId.
        ECPoint R = decompressKey(x, (recId & 1) == 1);
        //   1.4. If nR != point at infinity, then do another iteration of Step 1 (callers responsibility).
        if (!R.multiply(n).isInfinity())
            return null;
        //   1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
        BigInteger e = message.toBigInteger();
        //   1.6. For k from 1 to 2 do the following.   (loop is outside this function via iterating recId)
        //   1.6.1. Compute a candidate public key as:
        //               Q = mi(r) * (sR - eG)
        //
        // Where mi(x) is the modular multiplicative inverse. We transform this into the following:
        //               Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
        // Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n). In the above equation
        // ** is point multiplication and + is point addition (the EC group operator).
        //
        // We can find the additive inverse by subtracting e from zero then taking the mod. For example the additive
        // inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 = 8.
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = sig.r.modInverse(n);
        BigInteger srInv = rInv.multiply(sig.s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv);
        return ECKey.fromPublicOnly(q.getEncoded(compressed));
    }

    /** Decompress a compressed public key (x co-ord and low-bit of y-coord). */
    private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
        compEnc[0] = (byte)(yBit ? 0x03 : 0x02);
        return CURVE.getCurve().decodePoint(compEnc);
    }

    /**
     * Returns a 32 byte array containing the private key.
     * @throws org.bitcoinj.core.ECKey.MissingPrivateKeyException if the private key bytes are missing/encrypted.
     */
    public byte[] getPrivKeyBytes() {
        return Utils.bigIntegerToBytes(getPrivKey(), 32);
    }

    /**
     * Exports the private key in the form used by the Satoshi client "dumpprivkey" and "importprivkey" commands. Use
     * the {@link org.bitcoinj.core.DumpedPrivateKey#toString()} method to get the string.
     *
     * @param params The network this key is intended for use on.
     * @return Private key bytes as a {@link DumpedPrivateKey}.
     * @throws IllegalStateException if the private key is not available.
     */
    public DumpedPrivateKey getPrivateKeyEncoded(NetworkParameters params) {
        return new DumpedPrivateKey(params, getPrivKeyBytes(), isCompressed());
    }

    /**
     * Returns the creation time of this key or zero if the key was deserialized from a version that did not store
     * that data.
     */
    @Override
    public long getCreationTimeSeconds() {
        return creationTimeSeconds;
    }

    /**
     * Sets the creation time of this key. Zero is a convention to mean "unavailable". This method can be useful when
     * you have a raw key you are importing from somewhere else.
     */
    public void setCreationTimeSeconds(long newCreationTimeSeconds) {
        if (newCreationTimeSeconds < 0)
            throw new IllegalArgumentException("Cannot set creation time to negative value: " + newCreationTimeSeconds);
        creationTimeSeconds = newCreationTimeSeconds;
    }

    /**
     * Create an encrypted private key with the keyCrypter and the AES key supplied.
     * This method returns a new encrypted key and leaves the original unchanged.
     *
     * @param keyCrypter The keyCrypter that specifies exactly how the encrypted bytes are created.
     * @param aesKey The KeyParameter with the AES encryption key (usually constructed with keyCrypter#deriveKey and cached as it is slow to create).
     * @return encryptedKey
     */
    public ECKey encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) throws KeyCrypterException {
        checkNotNull(keyCrypter);
        final byte[] privKeyBytes = getPrivKeyBytes();
        EncryptedData encryptedPrivateKey = keyCrypter.encrypt(privKeyBytes, aesKey);
        ECKey result = ECKey.fromEncrypted(encryptedPrivateKey, keyCrypter, getPubKey());
        result.setCreationTimeSeconds(creationTimeSeconds);
        return result;
    }

    /**
     * Create a decrypted private key with the keyCrypter and AES key supplied. Note that if the aesKey is wrong, this
     * has some chance of throwing KeyCrypterException due to the corrupted padding that will result, but it can also
     * just yield a garbage key.
     *
     * @param keyCrypter The keyCrypter that specifies exactly how the decrypted bytes are created.
     * @param aesKey The KeyParameter with the AES encryption key (usually constructed with keyCrypter#deriveKey and cached).
     */
    public ECKey decrypt(KeyCrypter keyCrypter, KeyParameter aesKey) throws KeyCrypterException {
        checkNotNull(keyCrypter);
        // Check that the keyCrypter matches the one used to encrypt the keys, if set.
        if (this.keyCrypter != null && !this.keyCrypter.equals(keyCrypter))
            throw new KeyCrypterException("The keyCrypter being used to decrypt the key is different to the one that was used to encrypt it");
        checkState(encryptedPrivateKey != null, "This key is not encrypted");
        byte[] unencryptedPrivateKey = keyCrypter.decrypt(encryptedPrivateKey, aesKey);
        ECKey key = ECKey.fromPrivate(unencryptedPrivateKey);
        if (!isCompressed())
            key = key.decompress();
        if (!Arrays.equals(key.getPubKey(), getPubKey()))
            throw new KeyCrypterException("Provided AES key is wrong");
        key.setCreationTimeSeconds(creationTimeSeconds);
        return key;
    }

    /**
     * Create a decrypted private key with AES key. Note that if the AES key is wrong, this
     * has some chance of throwing KeyCrypterException due to the corrupted padding that will result, but it can also
     * just yield a garbage key.
     *
     * @param aesKey The KeyParameter with the AES encryption key (usually constructed with keyCrypter#deriveKey and cached).
     */
    public ECKey decrypt(KeyParameter aesKey) throws KeyCrypterException {
        final KeyCrypter crypter = getKeyCrypter();
        if (crypter == null)
            throw new KeyCrypterException("No key crypter available");
        return decrypt(crypter, aesKey);
    }

    /**
     * Creates decrypted private key if needed.
     */
    public ECKey maybeDecrypt(@Nullable KeyParameter aesKey) throws KeyCrypterException {
        return isEncrypted() && aesKey != null ? decrypt(aesKey) : this;
    }

    /**
     * <p>Check that it is possible to decrypt the key with the keyCrypter and that the original key is returned.</p>
     *
     * <p>Because it is a critical failure if the private keys cannot be decrypted successfully (resulting of loss of all
     * bitcoins controlled by the private key) you can use this method to check when you *encrypt* a wallet that
     * it can definitely be decrypted successfully.</p>
     *
     * <p>See {@link Wallet#encrypt(KeyCrypter keyCrypter, KeyParameter aesKey)} for example usage.</p>
     *
     * @return true if the encrypted key can be decrypted back to the original key successfully.
     */
    public static boolean encryptionIsReversible(ECKey originalKey, ECKey encryptedKey, KeyCrypter keyCrypter, KeyParameter aesKey) {
        try {
            ECKey rebornUnencryptedKey = encryptedKey.decrypt(keyCrypter, aesKey);
            byte[] originalPrivateKeyBytes = originalKey.getPrivKeyBytes();
            byte[] rebornKeyBytes = rebornUnencryptedKey.getPrivKeyBytes();
            if (!Arrays.equals(originalPrivateKeyBytes, rebornKeyBytes)) {
                log.error("The check that encryption could be reversed failed for {}", originalKey);
                return false;
            }
            return true;
        } catch (KeyCrypterException kce) {
            log.error(kce.getMessage());
            return false;
        }
    }

    /**
     * Indicates whether the private key is encrypted (true) or not (false).
     * A private key is deemed to be encrypted when there is both a KeyCrypter and the encryptedPrivateKey is non-zero.
     */
    @Override
    public boolean isEncrypted() {
        return keyCrypter != null && encryptedPrivateKey != null && encryptedPrivateKey.encryptedBytes.length > 0;
    }

    @Nullable
    @Override
    public Protos.Wallet.EncryptionType getEncryptionType() {
        return keyCrypter != null ? keyCrypter.getUnderstoodEncryptionType() : Protos.Wallet.EncryptionType.UNENCRYPTED;
    }

    /**
     * A wrapper for {@link #getPrivKeyBytes()} that returns null if the private key bytes are missing or would have
     * to be derived (for the HD key case).
     */
    @Override
    @Nullable
    public byte[] getSecretBytes() {
        if (hasPrivKey())
            return getPrivKeyBytes();
        else
            return null;
    }

    /** An alias for {@link #getEncryptedPrivateKey()} */
    @Nullable
    @Override
    public EncryptedData getEncryptedData() {
        return getEncryptedPrivateKey();
    }

    /**
     * Returns the the encrypted private key bytes and initialisation vector for this ECKey, or null if the ECKey
     * is not encrypted.
     */
    @Nullable
    public EncryptedData getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }

    /**
     * Returns the KeyCrypter that was used to encrypt to encrypt this ECKey. You need this to decrypt the ECKey.
     */
    @Nullable
    public KeyCrypter getKeyCrypter() {
        return keyCrypter;
    }

    public static class MissingPrivateKeyException extends RuntimeException {
    }

    public static class KeyIsEncryptedException extends MissingPrivateKeyException {
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof ECKey)) return false;

        ECKey other = (ECKey) o;

        return Objects.equal(this.priv, other.priv)
                && Objects.equal(this.pub, other.pub)
                && Objects.equal(this.creationTimeSeconds, other.creationTimeSeconds)
                && Objects.equal(this.keyCrypter, other.keyCrypter)
                && Objects.equal(this.encryptedPrivateKey, other.encryptedPrivateKey);
    }

    @Override
    public int hashCode() {
        // Public keys are random already so we can just use a part of them as the hashcode. Read from the start to
        // avoid picking up the type code (compressed vs uncompressed) which is tacked on the end.
        byte[] bits = getPubKey();
        return (bits[0] & 0xFF) | ((bits[1] & 0xFF) << 8) | ((bits[2] & 0xFF) << 16) | ((bits[3] & 0xFF) << 24);
    }

    @Override
    public String toString() {
        return toString(false);
    }

    /**
     * Produce a string rendering of the ECKey INCLUDING the private key.
     * Unless you absolutely need the private key it is better for security reasons to just use {@link #toString()}.
     */
    public String toStringWithPrivate() {
        return toString(true);
    }

    private String toString(boolean includePrivate) {
        final ToStringHelper helper = Objects.toStringHelper(this).omitNullValues();
        helper.add("pub", Utils.HEX.encode(pub.getEncoded()));
        if (includePrivate) {
            try {
                helper.add("priv", Utils.HEX.encode(getPrivKey().toByteArray()));
            } catch (IllegalStateException e) {
                // TODO: Make hasPrivKey() work for deterministic keys and fix this.
            }
        }
        if (creationTimeSeconds > 0)
            helper.add("creationTimeSeconds", creationTimeSeconds);
        helper.add("keyCrypter", keyCrypter);
        if (includePrivate)
            helper.add("encryptedPrivateKey", encryptedPrivateKey);
        helper.add("isEncrypted", isEncrypted());
        helper.add("isPubKeyOnly", isPubKeyOnly());
        return helper.toString();
    }
}
