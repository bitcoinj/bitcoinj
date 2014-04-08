package org.bouncycastle.crypto.examples;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.jpake.JPAKEPrimeOrderGroup;
import org.bouncycastle.crypto.agreement.jpake.JPAKEPrimeOrderGroups;
import org.bouncycastle.crypto.agreement.jpake.JPAKEParticipant;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound1Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound2Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound3Payload;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * An example of a J-PAKE exchange.
 * <p>
 * 
 * In this example, both Alice and Bob are on the same computer (in the same JVM, in fact).
 * In reality, Alice and Bob would be in different locations,
 * and would be sending their generated payloads to each other.
 */
public class JPAKEExample
{

    public static void main(String args[]) throws CryptoException
    {
        /*
         * Initialization
         * 
         * Pick an appropriate prime order group to use throughout the exchange.
         * Note that both participants must use the same group.
         */
        JPAKEPrimeOrderGroup group = JPAKEPrimeOrderGroups.NIST_3072;

        BigInteger p = group.getP();
        BigInteger q = group.getQ();
        BigInteger g = group.getG();

        String alicePassword = "password";
        String bobPassword = "password";

        System.out.println("********* Initialization **********");
        System.out.println("Public parameters for the cyclic group:");
        System.out.println("p (" + p.bitLength() + " bits): " + p.toString(16));
        System.out.println("q (" + q.bitLength() + " bits): " + q.toString(16));
        System.out.println("g (" + p.bitLength() + " bits): " + g.toString(16));
        System.out.println("p mod q = " + p.mod(q).toString(16));
        System.out.println("g^{q} mod p = " + g.modPow(q, p).toString(16));
        System.out.println("");

        System.out.println("(Secret passwords used by Alice and Bob: " +
                "\"" + alicePassword + "\" and \"" + bobPassword + "\")\n");

        /*
         * Both participants must use the same hashing algorithm.
         */
        Digest digest = new SHA256Digest();
        SecureRandom random = new SecureRandom();

        JPAKEParticipant alice = new JPAKEParticipant("alice", alicePassword.toCharArray(), group, digest, random);
        JPAKEParticipant bob = new JPAKEParticipant("bob", bobPassword.toCharArray(), group, digest, random);

        /*
         * Round 1
         * 
         * Alice and Bob each generate a round 1 payload, and send it to each other.
         */

        JPAKERound1Payload aliceRound1Payload = alice.createRound1PayloadToSend();
        JPAKERound1Payload bobRound1Payload = bob.createRound1PayloadToSend();

        System.out.println("************ Round 1 **************");
        System.out.println("Alice sends to Bob: ");
        System.out.println("g^{x1}=" + aliceRound1Payload.getGx1().toString(16));
        System.out.println("g^{x2}=" + aliceRound1Payload.getGx2().toString(16));
        System.out.println("KP{x1}={" + aliceRound1Payload.getKnowledgeProofForX1()[0].toString(16) + "};{" + aliceRound1Payload.getKnowledgeProofForX1()[1].toString(16) + "}");
        System.out.println("KP{x2}={" + aliceRound1Payload.getKnowledgeProofForX2()[0].toString(16) + "};{" + aliceRound1Payload.getKnowledgeProofForX2()[1].toString(16) + "}");
        System.out.println("");

        System.out.println("Bob sends to Alice: ");
        System.out.println("g^{x3}=" + bobRound1Payload.getGx1().toString(16));
        System.out.println("g^{x4}=" + bobRound1Payload.getGx2().toString(16));
        System.out.println("KP{x3}={" + bobRound1Payload.getKnowledgeProofForX1()[0].toString(16) + "};{" + bobRound1Payload.getKnowledgeProofForX1()[1].toString(16) + "}");
        System.out.println("KP{x4}={" + bobRound1Payload.getKnowledgeProofForX2()[0].toString(16) + "};{" + bobRound1Payload.getKnowledgeProofForX2()[1].toString(16) + "}");
        System.out.println("");

        /*
         * Each participant must then validate the received payload for round 1
         */

        alice.validateRound1PayloadReceived(bobRound1Payload);
        System.out.println("Alice checks g^{x4}!=1: OK");
        System.out.println("Alice checks KP{x3}: OK");
        System.out.println("Alice checks KP{x4}: OK");
        System.out.println("");

        bob.validateRound1PayloadReceived(aliceRound1Payload);
        System.out.println("Bob checks g^{x2}!=1: OK");
        System.out.println("Bob checks KP{x1},: OK");
        System.out.println("Bob checks KP{x2},: OK");
        System.out.println("");

        /*
         * Round 2
         * 
         * Alice and Bob each generate a round 2 payload, and send it to each other.
         */

        JPAKERound2Payload aliceRound2Payload = alice.createRound2PayloadToSend();
        JPAKERound2Payload bobRound2Payload = bob.createRound2PayloadToSend();

        System.out.println("************ Round 2 **************");
        System.out.println("Alice sends to Bob: ");
        System.out.println("A=" + aliceRound2Payload.getA().toString(16));
        System.out.println("KP{x2*s}={" + aliceRound2Payload.getKnowledgeProofForX2s()[0].toString(16) + "},{" + aliceRound2Payload.getKnowledgeProofForX2s()[1].toString(16) + "}");
        System.out.println("");

        System.out.println("Bob sends to Alice");
        System.out.println("B=" + bobRound2Payload.getA().toString(16));
        System.out.println("KP{x4*s}={" + bobRound2Payload.getKnowledgeProofForX2s()[0].toString(16) + "},{" + bobRound2Payload.getKnowledgeProofForX2s()[1].toString(16) + "}");
        System.out.println("");

        /*
         * Each participant must then validate the received payload for round 2
         */

        alice.validateRound2PayloadReceived(bobRound2Payload);
        System.out.println("Alice checks KP{x4*s}: OK\n");

        bob.validateRound2PayloadReceived(aliceRound2Payload);
        System.out.println("Bob checks KP{x2*s}: OK\n");

        /*
         * After round 2, each participant computes the keying material.
         */

        BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
        BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

        System.out.println("********* After round 2 ***********");
        System.out.println("Alice computes key material \t K=" + aliceKeyingMaterial.toString(16));
        System.out.println("Bob computes key material \t K=" + bobKeyingMaterial.toString(16));
        System.out.println();
        
        
        /*
         * You must derive a session key from the keying material applicable
         * to whatever encryption algorithm you want to use.
         */
        
        BigInteger aliceKey = deriveSessionKey(aliceKeyingMaterial);
        BigInteger bobKey = deriveSessionKey(bobKeyingMaterial);
        
        /*
         * At this point, you can stop and use the session keys if you want.
         * This is implicit key confirmation.
         * 
         * If you want to explicitly confirm that the key material matches,
         * you can continue on and perform round 3.
         */
        
        /*
         * Round 3
         * 
         * Alice and Bob each generate a round 3 payload, and send it to each other.
         */

        JPAKERound3Payload aliceRound3Payload = alice.createRound3PayloadToSend(aliceKeyingMaterial);
        JPAKERound3Payload bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

        System.out.println("************ Round 3 **************");
        System.out.println("Alice sends to Bob: ");
        System.out.println("MacTag=" + aliceRound3Payload.getMacTag().toString(16));
        System.out.println("");
        System.out.println("Bob sends to Alice: ");
        System.out.println("MacTag=" + bobRound3Payload.getMacTag().toString(16));
        System.out.println("");

        /*
         * Each participant must then validate the received payload for round 3
         */

        alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
        System.out.println("Alice checks MacTag: OK\n");

        bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);
        System.out.println("Bob checks MacTag: OK\n");

        System.out.println();
        System.out.println("MacTags validated, therefore the keying material matches.");
    }

    private static BigInteger deriveSessionKey(BigInteger keyingMaterial)
    {
        /*
         * You should use a secure key derivation function (KDF) to derive the session key.
         * 
         * For the purposes of this example, I'm just going to use a hash of the keying material.
         */
        SHA256Digest digest = new SHA256Digest();
        
        byte[] keyByteArray = keyingMaterial.toByteArray();
        
        byte[] output = new byte[digest.getDigestSize()];
        
        digest.update(keyByteArray, 0, keyByteArray.length);

        digest.doFinal(output, 0);

        return new BigInteger(output);
    }
}
