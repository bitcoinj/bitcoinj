package org.bouncycastle.crypto.agreement.jpake;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

/**
 * Primitives needed for a J-PAKE exchange.
 * <p>
 * The recommended way to perform a J-PAKE exchange is by using
 * two {@link JPAKEParticipant}s.  Internally, those participants
 * call these primitive operations in {@link JPAKEUtil}.
 * <p>
 * The primitives, however, can be used without a {@link JPAKEParticipant}
 * if needed.
 */
public class JPAKEUtil
{
    static final BigInteger ZERO = BigInteger.valueOf(0);
    static final BigInteger ONE = BigInteger.valueOf(1);

    /**
     * Return a value that can be used as x1 or x3 during round 1.
     * <p>
     * The returned value is a random value in the range <tt>[0, q-1]</tt>.
     */
    public static BigInteger generateX1(
        BigInteger q,
        SecureRandom random)
    {
        BigInteger min = ZERO;
        BigInteger max = q.subtract(ONE);
        return BigIntegers.createRandomInRange(min, max, random);
    }

    /**
     * Return a value that can be used as x2 or x4 during round 1.
     * <p>
     * The returned value is a random value in the range <tt>[1, q-1]</tt>.
     */
    public static BigInteger generateX2(
        BigInteger q,
        SecureRandom random)
    {
        BigInteger min = ONE;
        BigInteger max = q.subtract(ONE);
        return BigIntegers.createRandomInRange(min, max, random);
    }

    /**
     * Converts the given password to a {@link BigInteger}
     * for use in arithmetic calculations.
     */
    public static BigInteger calculateS(char[] password)
    {
        return new BigInteger(Strings.toUTF8ByteArray(password));
    }

    /**
     * Calculate g^x mod p as done in round 1.
     */
    public static BigInteger calculateGx(
        BigInteger p,
        BigInteger g,
        BigInteger x)
    {
        return g.modPow(x, p);
    }


    /**
     * Calculate ga as done in round 2.
     */
    public static BigInteger calculateGA(
        BigInteger p,
        BigInteger gx1,
        BigInteger gx3,
        BigInteger gx4)
    {
        // ga = g^(x1+x3+x4) = g^x1 * g^x3 * g^x4 
        return gx1.multiply(gx3).multiply(gx4).mod(p);
    }


    /**
     * Calculate x2 * s as done in round 2.
     */
    public static BigInteger calculateX2s(
        BigInteger q,
        BigInteger x2,
        BigInteger s)
    {
        return x2.multiply(s).mod(q);
    }


    /**
     * Calculate A as done in round 2.
     */
    public static BigInteger calculateA(
        BigInteger p,
        BigInteger q,
        BigInteger gA,
        BigInteger x2s)
    {
        // A = ga^(x*s)
        return gA.modPow(x2s, p);
    }

    /**
     * Calculate a zero knowledge proof of x using Schnorr's signature.
     * The returned array has two elements {g^v, r = v-x*h} for x.
     */
    public static BigInteger[] calculateZeroKnowledgeProof(
        BigInteger p,
        BigInteger q,
        BigInteger g,
        BigInteger gx,
        BigInteger x,
        String participantId,
        Digest digest,
        SecureRandom random)
    {
        BigInteger[] zeroKnowledgeProof = new BigInteger[2];

        /* Generate a random v, and compute g^v */
        BigInteger vMin = ZERO;
        BigInteger vMax = q.subtract(ONE);
        BigInteger v = BigIntegers.createRandomInRange(vMin, vMax, random);

        BigInteger gv = g.modPow(v, p);
        BigInteger h = calculateHashForZeroKnowledgeProof(g, gv, gx, participantId, digest); // h

        zeroKnowledgeProof[0] = gv;
        zeroKnowledgeProof[1] = v.subtract(x.multiply(h)).mod(q); // r = v-x*h

        return zeroKnowledgeProof;
    }

    private static BigInteger calculateHashForZeroKnowledgeProof(
        BigInteger g,
        BigInteger gr,
        BigInteger gx,
        String participantId,
        Digest digest)
    {
        digest.reset();

        updateDigestIncludingSize(digest, g);

        updateDigestIncludingSize(digest, gr);

        updateDigestIncludingSize(digest, gx);

        updateDigestIncludingSize(digest, participantId);

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return new BigInteger(output);
    }

    /**
     * Validates that g^x4 is not 1.
     *
     * @throws CryptoException if g^x4 is 1
     */
    public static void validateGx4(BigInteger gx4)
        throws CryptoException
    {
        if (gx4.equals(ONE))
        {
            throw new CryptoException("g^x validation failed.  g^x should not be 1.");
        }
    }

    /**
     * Validates that ga is not 1.
     * <p>
     * As described by Feng Hao...
     * <p>
     * <blockquote>
     * Alice could simply check ga != 1 to ensure it is a generator.
     * In fact, as we will explain in Section 3, (x1 + x3 + x4 ) is random over Zq even in the face of active attacks.
     * Hence, the probability for ga = 1 is extremely small - on the order of 2^160 for 160-bit q.
     * </blockquote>
     *
     * @throws CryptoException if ga is 1
     */
    public static void validateGa(BigInteger ga)
        throws CryptoException
    {
        if (ga.equals(ONE))
        {
            throw new CryptoException("ga is equal to 1.  It should not be.  The chances of this happening are on the order of 2^160 for a 160-bit q.  Try again.");
        }
    }

    /**
     * Validates the zero knowledge proof (generated by
     * {@link #calculateZeroKnowledgeProof(BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, String, Digest, SecureRandom)})
     * is correct.
     *
     * @throws CryptoException if the zero knowledge proof is not correct
     */
    public static void validateZeroKnowledgeProof(
        BigInteger p,
        BigInteger q,
        BigInteger g,
        BigInteger gx,
        BigInteger[] zeroKnowledgeProof,
        String participantId,
        Digest digest)
        throws CryptoException
    {

        /* sig={g^v,r} */
        BigInteger gv = zeroKnowledgeProof[0];
        BigInteger r = zeroKnowledgeProof[1];

        BigInteger h = calculateHashForZeroKnowledgeProof(g, gv, gx, participantId, digest);
        if (!(gx.compareTo(ZERO) == 1 && // g^x > 0
            gx.compareTo(p) == -1 && // g^x < p
            gx.modPow(q, p).compareTo(ONE) == 0 && // g^x^q mod q = 1
                /*
                 * Below, I took an straightforward way to compute g^r * g^x^h,
                 * which needs 2 exp. Using a simultaneous computation technique
                 * would only need 1 exp.
                 */
            g.modPow(r, p).multiply(gx.modPow(h, p)).mod(p).compareTo(gv) == 0)) // g^v=g^r * g^x^h
        {
            throw new CryptoException("Zero-knowledge proof validation failed");
        }
    }

    /**
     * Calculates the keying material, which can be done after round 2 has completed.
     * A session key must be derived from this key material using a secure key derivation function (KDF).
     * The KDF used to derive the key is handled externally (i.e. not by {@link JPAKEParticipant}).
     * <pre>
     * KeyingMaterial = (B/g^{x2*x4*s})^x2
     * </pre>
     */
    public static BigInteger calculateKeyingMaterial(
        BigInteger p,
        BigInteger q,
        BigInteger gx4,
        BigInteger x2,
        BigInteger s,
        BigInteger B)
    {
        return gx4.modPow(x2.multiply(s).negate().mod(q), p).multiply(B).modPow(x2, p);
    }

    /**
     * Validates that the given participant ids are not equal.
     * (For the J-PAKE exchange, each participant must use a unique id.)
     *
     * @throws CryptoException if the participantId strings are equal.
     */
    public static void validateParticipantIdsDiffer(String participantId1, String participantId2)
        throws CryptoException
    {
        if (participantId1.equals(participantId2))
        {
            throw new CryptoException(
                "Both participants are using the same participantId ("
                    + participantId1
                    + "). This is not allowed. "
                    + "Each participant must use a unique participantId.");
        }
    }

    /**
     * Validates that the given participant ids are equal.
     * This is used to ensure that the payloads received from
     * each round all come from the same participant.
     *
     * @throws CryptoException if the participantId strings are equal.
     */
    public static void validateParticipantIdsEqual(String expectedParticipantId, String actualParticipantId)
        throws CryptoException
    {
        if (!expectedParticipantId.equals(actualParticipantId))
        {
            throw new CryptoException(
                "Received payload from incorrect partner ("
                    + actualParticipantId
                    + "). Expected to receive payload from "
                    + expectedParticipantId
                    + ".");
        }
    }

    /**
     * Validates that the given object is not null.
     *
     *  @param object object in question
     * @param description name of the object (to be used in exception message)
     * @throws NullPointerException if the object is null.
     */
    public static void validateNotNull(Object object, String description)
    {
        if (object == null)
        {
            throw new NullPointerException(description + " must not be null");
        }
    }

    /**
     * Calculates the MacTag (to be used for key confirmation), as defined by
     * <a href="http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf">NIST SP 800-56A Revision 1</a>,
     * Section 8.2 Unilateral Key Confirmation for Key Agreement Schemes.
     * <pre>
     * MacTag = HMAC(MacKey, MacLen, MacData)
     *
     * MacKey = H(K || "JPAKE_KC")
     *
     * MacData = "KC_1_U" || participantId || partnerParticipantId || gx1 || gx2 || gx3 || gx4
     *
     * Note that both participants use "KC_1_U" because the sender of the round 3 message
     * is always the initiator for key confirmation.
     *
     * HMAC = {@link HMac} used with the given {@link Digest}
     * H = The given {@link Digest}
     * MacLen = length of MacTag
     * </pre>
     */
    public static BigInteger calculateMacTag(
        String participantId,
        String partnerParticipantId,
        BigInteger gx1,
        BigInteger gx2,
        BigInteger gx3,
        BigInteger gx4,
        BigInteger keyingMaterial,
        Digest digest)
    {
        byte[] macKey = calculateMacKey(
            keyingMaterial,
            digest);

        HMac mac = new HMac(digest);
        byte[] macOutput = new byte[mac.getMacSize()];
        mac.init(new KeyParameter(macKey));
        
        /*
         * MacData = "KC_1_U" || participantId_Alice || participantId_Bob || gx1 || gx2 || gx3 || gx4.
         */
        updateMac(mac, "KC_1_U");
        updateMac(mac, participantId);
        updateMac(mac, partnerParticipantId);
        updateMac(mac, gx1);
        updateMac(mac, gx2);
        updateMac(mac, gx3);
        updateMac(mac, gx4);

        mac.doFinal(macOutput, 0);

        Arrays.fill(macKey, (byte)0);

        return new BigInteger(macOutput);

    }

    /**
     * Calculates the MacKey (i.e. the key to use when calculating the MagTag for key confirmation).
     * <pre>
     * MacKey = H(K || "JPAKE_KC")
     * </pre>
     */
    private static byte[] calculateMacKey(BigInteger keyingMaterial, Digest digest)
    {
        digest.reset();

        updateDigest(digest, keyingMaterial);
        /*
         * This constant is used to ensure that the macKey is NOT the same as the derived key.
         */
        updateDigest(digest, "JPAKE_KC");

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return output;
    }

    /**
     * Validates the MacTag received from the partner participant.
     *
     * @param partnerMacTag the MacTag received from the partner.
     * @throws CryptoException if the participantId strings are equal.
     */
    public static void validateMacTag(
        String participantId,
        String partnerParticipantId,
        BigInteger gx1,
        BigInteger gx2,
        BigInteger gx3,
        BigInteger gx4,
        BigInteger keyingMaterial,
        Digest digest,
        BigInteger partnerMacTag)
        throws CryptoException
    {
        /*
         * Calculate the expected MacTag using the parameters as the partner
         * would have used when the partner called calculateMacTag.
         * 
         * i.e. basically all the parameters are reversed.
         * participantId <-> partnerParticipantId
         *            x1 <-> x3
         *            x2 <-> x4
         */
        BigInteger expectedMacTag = calculateMacTag(
            partnerParticipantId,
            participantId,
            gx3,
            gx4,
            gx1,
            gx2,
            keyingMaterial,
            digest);

        if (!expectedMacTag.equals(partnerMacTag))
        {
            throw new CryptoException(
                "Partner MacTag validation failed. "
                    + "Therefore, the password, MAC, or digest algorithm of each participant does not match.");
        }
    }

    private static void updateDigest(Digest digest, BigInteger bigInteger)
    {
        byte[] byteArray = BigIntegers.asUnsignedByteArray(bigInteger);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateDigestIncludingSize(Digest digest, BigInteger bigInteger)
    {
        byte[] byteArray = BigIntegers.asUnsignedByteArray(bigInteger);
        digest.update(intToByteArray(byteArray.length), 0, 4);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateDigest(Digest digest, String string)
    {
        byte[] byteArray = Strings.toUTF8ByteArray(string);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateDigestIncludingSize(Digest digest, String string)
    {
        byte[] byteArray = Strings.toUTF8ByteArray(string);
        digest.update(intToByteArray(byteArray.length), 0, 4);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateMac(Mac mac, BigInteger bigInteger)
    {
        byte[] byteArray = BigIntegers.asUnsignedByteArray(bigInteger);
        mac.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateMac(Mac mac, String string)
    {
        byte[] byteArray = Strings.toUTF8ByteArray(string);
        mac.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static byte[] intToByteArray(int value)
    {
        return new byte[]{
            (byte)(value >>> 24),
            (byte)(value >>> 16),
            (byte)(value >>> 8),
            (byte)value
        };
    }

}
