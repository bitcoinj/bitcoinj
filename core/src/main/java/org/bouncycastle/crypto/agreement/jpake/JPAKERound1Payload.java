package org.bouncycastle.crypto.agreement.jpake;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

/**
 * The payload sent/received during the first round of a J-PAKE exchange.
 * <p>
 * Each {@link JPAKEParticipant} creates and sends an instance
 * of this payload to the other {@link JPAKEParticipant}.
 * The payload to send should be created via
 * {@link JPAKEParticipant#createRound1PayloadToSend()}.
 * <p>
 * Each {@link JPAKEParticipant} must also validate the payload
 * received from the other {@link JPAKEParticipant}.
 * The received payload should be validated via
 * {@link JPAKEParticipant#validateRound1PayloadReceived(JPAKERound1Payload)}.
 */
public class JPAKERound1Payload
{
    /**
     * The id of the {@link JPAKEParticipant} who created/sent this payload.
     */
    private final String participantId;

    /**
     * The value of g^x1
     */
    private final BigInteger gx1;

    /**
     * The value of g^x2
     */
    private final BigInteger gx2;

    /**
     * The zero knowledge proof for x1.
     * <p/>
     * This is a two element array, containing {g^v, r} for x1.
     */
    private final BigInteger[] knowledgeProofForX1;

    /**
     * The zero knowledge proof for x2.
     * <p/>
     * This is a two element array, containing {g^v, r} for x2.
     */
    private final BigInteger[] knowledgeProofForX2;

    public JPAKERound1Payload(
        String participantId,
        BigInteger gx1,
        BigInteger gx2,
        BigInteger[] knowledgeProofForX1,
        BigInteger[] knowledgeProofForX2)
    {
        JPAKEUtil.validateNotNull(participantId, "participantId");
        JPAKEUtil.validateNotNull(gx1, "gx1");
        JPAKEUtil.validateNotNull(gx2, "gx2");
        JPAKEUtil.validateNotNull(knowledgeProofForX1, "knowledgeProofForX1");
        JPAKEUtil.validateNotNull(knowledgeProofForX2, "knowledgeProofForX2");

        this.participantId = participantId;
        this.gx1 = gx1;
        this.gx2 = gx2;
        this.knowledgeProofForX1 = Arrays.copyOf(knowledgeProofForX1, knowledgeProofForX1.length);
        this.knowledgeProofForX2 = Arrays.copyOf(knowledgeProofForX2, knowledgeProofForX2.length);
    }

    public String getParticipantId()
    {
        return participantId;
    }

    public BigInteger getGx1()
    {
        return gx1;
    }

    public BigInteger getGx2()
    {
        return gx2;
    }

    public BigInteger[] getKnowledgeProofForX1()
    {
        return Arrays.copyOf(knowledgeProofForX1, knowledgeProofForX1.length);
    }

    public BigInteger[] getKnowledgeProofForX2()
    {
        return Arrays.copyOf(knowledgeProofForX2, knowledgeProofForX2.length);
    }

}
