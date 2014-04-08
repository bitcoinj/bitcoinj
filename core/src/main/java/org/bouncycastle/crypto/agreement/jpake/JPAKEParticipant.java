package org.bouncycastle.crypto.agreement.jpake;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.Arrays;

/**
 * A participant in a Password Authenticated Key Exchange by Juggling (J-PAKE) exchange.
 * <p>
 * The J-PAKE exchange is defined by Feng Hao and Peter Ryan in the paper
 * <a href="http://grouper.ieee.org/groups/1363/Research/contributions/hao-ryan-2008.pdf">
 * "Password Authenticated Key Exchange by Juggling, 2008."</a>
 * <p>
 * The J-PAKE protocol is symmetric.
 * There is no notion of a <i>client</i> or <i>server</i>, but rather just two <i>participants</i>.
 * An instance of {@link JPAKEParticipant} represents one participant, and
 * is the primary interface for executing the exchange.
 * <p>
 * To execute an exchange, construct a {@link JPAKEParticipant} on each end,
 * and call the following 7 methods
 * (once and only once, in the given order, for each participant, sending messages between them as described):
 * <ol>
 * <li>{@link #createRound1PayloadToSend()} - and send the payload to the other participant</li>
 * <li>{@link #validateRound1PayloadReceived(JPAKERound1Payload)} - use the payload received from the other participant</li>
 * <li>{@link #createRound2PayloadToSend()} - and send the payload to the other participant</li>
 * <li>{@link #validateRound2PayloadReceived(JPAKERound2Payload)} - use the payload received from the other participant</li>
 * <li>{@link #calculateKeyingMaterial()}</li>
 * <li>{@link #createRound3PayloadToSend(BigInteger)} - and send the payload to the other participant</li>
 * <li>{@link #validateRound3PayloadReceived(JPAKERound3Payload, BigInteger)} - use the payload received from the other participant</li>
 * </ol>
 * <p>
 * Each side should derive a session key from the keying material returned by {@link #calculateKeyingMaterial()}.
 * The caller is responsible for deriving the session key using a secure key derivation function (KDF).
 * <p>
 * Round 3 is an optional key confirmation process.
 * If you do not execute round 3, then there is no assurance that both participants are using the same key.
 * (i.e. if the participants used different passwords, then their session keys will differ.)
 * <p>
 * If the round 3 validation succeeds, then the keys are guaranteed to be the same on both sides.
 * <p>
 * The symmetric design can easily support the asymmetric cases when one party initiates the communication.
 * e.g. Sometimes the round1 payload and round2 payload may be sent in one pass.
 * Also, in some cases, the key confirmation payload can be sent together with the round2 payload.
 * These are the trivial techniques to optimize the communication.
 * <p>
 * The key confirmation process is implemented as specified in
 * <a href="http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf">NIST SP 800-56A Revision 1</a>,
 * Section 8.2 Unilateral Key Confirmation for Key Agreement Schemes.
 * <p>
 * This class is stateful and NOT threadsafe.
 * Each instance should only be used for ONE complete J-PAKE exchange
 * (i.e. a new {@link JPAKEParticipant} should be constructed for each new J-PAKE exchange).
 * <p>
 * See {@link JPAKEExample} for example usage.
 */
public class JPAKEParticipant
{
    /*
     * Possible internal states.  Used for state checking.
     */

    public static final int STATE_INITIALIZED = 0;
    public static final int STATE_ROUND_1_CREATED = 10;
    public static final int STATE_ROUND_1_VALIDATED = 20;
    public static final int STATE_ROUND_2_CREATED = 30;
    public static final int STATE_ROUND_2_VALIDATED = 40;
    public static final int STATE_KEY_CALCULATED = 50;
    public static final int STATE_ROUND_3_CREATED = 60;
    public static final int STATE_ROUND_3_VALIDATED = 70;

    /**
     * Unique identifier of this participant.
     * The two participants in the exchange must NOT share the same id.
     */
    private final String participantId;

    /**
     * Shared secret.  This only contains the secret between construction
     * and the call to {@link #calculateKeyingMaterial()}.
     * <p/>
     * i.e. When {@link #calculateKeyingMaterial()} is called, this buffer overwritten with 0's,
     * and the field is set to null.
     */
    private char[] password;

    /**
     * Digest to use during calculations.
     */
    private final Digest digest;

    /**
     * Source of secure random data.
     */
    private final SecureRandom random;

    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger g;

    /**
     * The participantId of the other participant in this exchange.
     */
    private String partnerParticipantId;

    /**
     * Alice's x1 or Bob's x3.
     */
    private BigInteger x1;
    /**
     * Alice's x2 or Bob's x4.
     */
    private BigInteger x2;
    /**
     * Alice's g^x1 or Bob's g^x3.
     */
    private BigInteger gx1;
    /**
     * Alice's g^x2 or Bob's g^x4.
     */
    private BigInteger gx2;
    /**
     * Alice's g^x3 or Bob's g^x1.
     */
    private BigInteger gx3;
    /**
     * Alice's g^x4 or Bob's g^x2.
     */
    private BigInteger gx4;
    /**
     * Alice's B or Bob's A.
     */
    private BigInteger b;

    /**
     * The current state.
     * See the <tt>STATE_*</tt> constants for possible values.
     */
    private int state;

    /**
     * Convenience constructor for a new {@link JPAKEParticipant} that uses
     * the {@link JPAKEPrimeOrderGroups#NIST_3072} prime order group,
     * a SHA-256 digest, and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALIZED}.
     *
     * @param participantId unique identifier of this participant.
     *                      The two participants in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @throws NullPointerException if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public JPAKEParticipant(
        String participantId,
        char[] password)
    {
        this(
            participantId,
            password,
            JPAKEPrimeOrderGroups.NIST_3072);
    }


    /**
     * Convenience constructor for a new {@link JPAKEParticipant} that uses
     * a SHA-256 digest and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALIZED}.
     *
     * @param participantId unique identifier of this participant.
     *                      The two participants in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param group         prime order group.
     *                      See {@link JPAKEPrimeOrderGroups} for standard groups
     * @throws NullPointerException if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public JPAKEParticipant(
        String participantId,
        char[] password,
        JPAKEPrimeOrderGroup group)
    {
        this(
            participantId,
            password,
            group,
            new SHA256Digest(),
            new SecureRandom());
    }


    /**
     * Construct a new {@link JPAKEParticipant}.
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALIZED}.
     *
     * @param participantId unique identifier of this participant.
     *                      The two participants in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param group         prime order group.
     *                      See {@link JPAKEPrimeOrderGroups} for standard groups
     * @param digest        digest to use during zero knowledge proofs and key confirmation (SHA-256 or stronger preferred)
     * @param random        source of secure random data for x1 and x2, and for the zero knowledge proofs
     * @throws NullPointerException if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public JPAKEParticipant(
        String participantId,
        char[] password,
        JPAKEPrimeOrderGroup group,
        Digest digest,
        SecureRandom random)
    {
        JPAKEUtil.validateNotNull(participantId, "participantId");
        JPAKEUtil.validateNotNull(password, "password");
        JPAKEUtil.validateNotNull(group, "p");
        JPAKEUtil.validateNotNull(digest, "digest");
        JPAKEUtil.validateNotNull(random, "random");
        if (password.length == 0)
        {
            throw new IllegalArgumentException("Password must not be empty.");
        }

        this.participantId = participantId;
        
        /*
         * Create a defensive copy so as to fully encapsulate the password.
         * 
         * This array will contain the password for the lifetime of this
         * participant BEFORE {@link #calculateKeyingMaterial()} is called.
         * 
         * i.e. When {@link #calculateKeyingMaterial()} is called, the array will be cleared
         * in order to remove the password from memory.
         * 
         * The caller is responsible for clearing the original password array
         * given as input to this constructor.
         */
        this.password = Arrays.copyOf(password, password.length);

        this.p = group.getP();
        this.q = group.getQ();
        this.g = group.getG();

        this.digest = digest;
        this.random = random;

        this.state = STATE_INITIALIZED;
    }

    /**
     * Gets the current state of this participant.
     * See the <tt>STATE_*</tt> constants for possible values.
     */
    public int getState()
    {
        return this.state;
    }

    /**
     * Creates and returns the payload to send to the other participant during round 1.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_1_CREATED}.
     */
    public JPAKERound1Payload createRound1PayloadToSend()
    {
        if (this.state >= STATE_ROUND_1_CREATED)
        {
            throw new IllegalStateException("Round1 payload already created for " + participantId);
        }

        this.x1 = JPAKEUtil.generateX1(q, random);
        this.x2 = JPAKEUtil.generateX2(q, random);

        this.gx1 = JPAKEUtil.calculateGx(p, g, x1);
        this.gx2 = JPAKEUtil.calculateGx(p, g, x2);
        BigInteger[] knowledgeProofForX1 = JPAKEUtil.calculateZeroKnowledgeProof(p, q, g, gx1, x1, participantId, digest, random);
        BigInteger[] knowledgeProofForX2 = JPAKEUtil.calculateZeroKnowledgeProof(p, q, g, gx2, x2, participantId, digest, random);

        this.state = STATE_ROUND_1_CREATED;

        return new JPAKERound1Payload(participantId, gx1, gx2, knowledgeProofForX1, knowledgeProofForX2);
    }

    /**
     * Validates the payload received from the other participant during round 1.
     * <p>
     * Must be called prior to {@link #createRound2PayloadToSend()}.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_1_VALIDATED}.
     *
     * @throws CryptoException if validation fails.
     * @throws IllegalStateException if called multiple times.
     */
    public void validateRound1PayloadReceived(JPAKERound1Payload round1PayloadReceived)
        throws CryptoException
    {
        if (this.state >= STATE_ROUND_1_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for round1 payload for" + participantId);
        }
        this.partnerParticipantId = round1PayloadReceived.getParticipantId();
        this.gx3 = round1PayloadReceived.getGx1();
        this.gx4 = round1PayloadReceived.getGx2();

        BigInteger[] knowledgeProofForX3 = round1PayloadReceived.getKnowledgeProofForX1();
        BigInteger[] knowledgeProofForX4 = round1PayloadReceived.getKnowledgeProofForX2();

        JPAKEUtil.validateParticipantIdsDiffer(participantId, round1PayloadReceived.getParticipantId());
        JPAKEUtil.validateGx4(gx4);
        JPAKEUtil.validateZeroKnowledgeProof(p, q, g, gx3, knowledgeProofForX3, round1PayloadReceived.getParticipantId(), digest);
        JPAKEUtil.validateZeroKnowledgeProof(p, q, g, gx4, knowledgeProofForX4, round1PayloadReceived.getParticipantId(), digest);

        this.state = STATE_ROUND_1_VALIDATED;
    }

    /**
     * Creates and returns the payload to send to the other participant during round 2.
     * <p>
     * {@link #validateRound1PayloadReceived(JPAKERound1Payload)} must be called prior to this method.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_2_CREATED}.
     *
     * @throws IllegalStateException if called prior to {@link #validateRound1PayloadReceived(JPAKERound1Payload)}, or multiple times
     */
    public JPAKERound2Payload createRound2PayloadToSend()
    {
        if (this.state >= STATE_ROUND_2_CREATED)
        {
            throw new IllegalStateException("Round2 payload already created for " + this.participantId);
        }
        if (this.state < STATE_ROUND_1_VALIDATED)
        {
            throw new IllegalStateException("Round1 payload must be validated prior to creating Round2 payload for " + this.participantId);
        }
        BigInteger gA = JPAKEUtil.calculateGA(p, gx1, gx3, gx4);
        BigInteger s = JPAKEUtil.calculateS(password);
        BigInteger x2s = JPAKEUtil.calculateX2s(q, x2, s);
        BigInteger A = JPAKEUtil.calculateA(p, q, gA, x2s);
        BigInteger[] knowledgeProofForX2s = JPAKEUtil.calculateZeroKnowledgeProof(p, q, gA, A, x2s, participantId, digest, random);

        this.state = STATE_ROUND_2_CREATED;

        return new JPAKERound2Payload(participantId, A, knowledgeProofForX2s);
    }

    /**
     * Validates the payload received from the other participant during round 2.
     * <p>
     * Note that this DOES NOT detect a non-common password.
     * The only indication of a non-common password is through derivation
     * of different keys (which can be detected explicitly by executing round 3 and round 4)
     * <p>
     * Must be called prior to {@link #calculateKeyingMaterial()}.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_2_VALIDATED}.
     *
     * @throws CryptoException if validation fails.
     * @throws IllegalStateException if called prior to {@link #validateRound1PayloadReceived(JPAKERound1Payload)}, or multiple times
     */
    public void validateRound2PayloadReceived(JPAKERound2Payload round2PayloadReceived)
        throws CryptoException
    {
        if (this.state >= STATE_ROUND_2_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for round2 payload for" + participantId);
        }
        if (this.state < STATE_ROUND_1_VALIDATED)
        {
            throw new IllegalStateException("Round1 payload must be validated prior to validating Round2 payload for " + this.participantId);
        }
        BigInteger gB = JPAKEUtil.calculateGA(p, gx3, gx1, gx2);
        this.b = round2PayloadReceived.getA();
        BigInteger[] knowledgeProofForX4s = round2PayloadReceived.getKnowledgeProofForX2s();

        JPAKEUtil.validateParticipantIdsDiffer(participantId, round2PayloadReceived.getParticipantId());
        JPAKEUtil.validateParticipantIdsEqual(this.partnerParticipantId, round2PayloadReceived.getParticipantId());
        JPAKEUtil.validateGa(gB);
        JPAKEUtil.validateZeroKnowledgeProof(p, q, gB, b, knowledgeProofForX4s, round2PayloadReceived.getParticipantId(), digest);

        this.state = STATE_ROUND_2_VALIDATED;
    }

    /**
     * Calculates and returns the key material.
     * A session key must be derived from this key material using a secure key derivation function (KDF).
     * The KDF used to derive the key is handled externally (i.e. not by {@link JPAKEParticipant}).
     * <p>
     * The keying material will be identical for each participant if and only if
     * each participant's password is the same.  i.e. If the participants do not
     * share the same password, then each participant will derive a different key.
     * Therefore, if you immediately start using a key derived from
     * the keying material, then you must handle detection of incorrect keys.
     * If you want to handle this detection explicitly, you can optionally perform
     * rounds 3 and 4.  See {@link JPAKEParticipant} for details on how to execute
     * rounds 3 and 4.
     * <p>
     * The keying material will be in the range <tt>[0, p-1]</tt>.
     * <p>
     * {@link #validateRound2PayloadReceived(JPAKERound2Payload)} must be called prior to this method.
     * <p>
     * As a side effect, the internal {@link #password} array is cleared, since it is no longer needed.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_KEY_CALCULATED}.
     *
     * @throws IllegalStateException if called prior to {@link #validateRound2PayloadReceived(JPAKERound2Payload)},
     * or if called multiple times.
     */
    public BigInteger calculateKeyingMaterial()
    {
        if (this.state >= STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Key already calculated for " + participantId);
        }
        if (this.state < STATE_ROUND_2_VALIDATED)
        {
            throw new IllegalStateException("Round2 payload must be validated prior to creating key for " + participantId);
        }
        BigInteger s = JPAKEUtil.calculateS(password);
        
        /*
         * Clear the password array from memory, since we don't need it anymore.
         * 
         * Also set the field to null as a flag to indicate that the key has already been calculated.
         */
        Arrays.fill(password, (char)0);
        this.password = null;

        BigInteger keyingMaterial = JPAKEUtil.calculateKeyingMaterial(p, q, gx4, x2, s, b);
        
        /*
         * Clear the ephemeral private key fields as well.
         * Note that we're relying on the garbage collector to do its job to clean these up.
         * The old objects will hang around in memory until the garbage collector destroys them.
         * 
         * If the ephemeral private keys x1 and x2 are leaked,
         * the attacker might be able to brute-force the password.
         */
        this.x1 = null;
        this.x2 = null;
        this.b = null;
        
        /*
         * Do not clear gx* yet, since those are needed by round 3.
         */

        this.state = STATE_KEY_CALCULATED;

        return keyingMaterial;
    }


    /**
     * Creates and returns the payload to send to the other participant during round 3.
     * <p>
     * See {@link JPAKEParticipant} for more details on round 3.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_3_CREATED}.
     *
     * @param keyingMaterial The keying material as returned from {@link #calculateKeyingMaterial()}.
     * @throws IllegalStateException if called prior to {@link #calculateKeyingMaterial()}, or multiple times
     */
    public JPAKERound3Payload createRound3PayloadToSend(BigInteger keyingMaterial)
    {
        if (this.state >= STATE_ROUND_3_CREATED)
        {
            throw new IllegalStateException("Round3 payload already created for " + this.participantId);
        }
        if (this.state < STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Keying material must be calculated prior to creating Round3 payload for " + this.participantId);
        }

        BigInteger macTag = JPAKEUtil.calculateMacTag(
            this.participantId,
            this.partnerParticipantId,
            this.gx1,
            this.gx2,
            this.gx3,
            this.gx4,
            keyingMaterial,
            this.digest);

        this.state = STATE_ROUND_3_CREATED;

        return new JPAKERound3Payload(participantId, macTag);
    }

    /**
     * Validates the payload received from the other participant during round 3.
     * <p>
     * See {@link JPAKEParticipant} for more details on round 3.
     * <p>
     * After execution, the {@link #getState() state} will be {@link #STATE_ROUND_3_VALIDATED}.
     *
     * @param keyingMaterial The keying material as returned from {@link #calculateKeyingMaterial()}.
     * @throws CryptoException if validation fails.
     * @throws IllegalStateException if called prior to {@link #calculateKeyingMaterial()}, or multiple times
     */
    public void validateRound3PayloadReceived(JPAKERound3Payload round3PayloadReceived, BigInteger keyingMaterial)
        throws CryptoException
    {
        if (this.state >= STATE_ROUND_3_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for round3 payload for" + participantId);
        }
        if (this.state < STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Keying material must be calculated validated prior to validating Round3 payload for " + this.participantId);
        }
        JPAKEUtil.validateParticipantIdsDiffer(participantId, round3PayloadReceived.getParticipantId());
        JPAKEUtil.validateParticipantIdsEqual(this.partnerParticipantId, round3PayloadReceived.getParticipantId());

        JPAKEUtil.validateMacTag(
            this.participantId,
            this.partnerParticipantId,
            this.gx1,
            this.gx2,
            this.gx3,
            this.gx4,
            keyingMaterial,
            this.digest,
            round3PayloadReceived.getMacTag());
        
        
        /*
         * Clear the rest of the fields.
         */
        this.gx1 = null;
        this.gx2 = null;
        this.gx3 = null;
        this.gx4 = null;

        this.state = STATE_ROUND_3_VALIDATED;
    }

}
