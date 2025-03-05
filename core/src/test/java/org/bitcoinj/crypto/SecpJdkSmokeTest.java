package org.bitcoinj.crypto;

import org.bitcoinj.secp.api.P256K1KeyPair;
import org.bitcoinj.secp.api.Secp256k1;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

/**
 * A quick test to make sure we can load and execute the secp-api and secp-bouncy.
 */
public class SecpJdkSmokeTest {
    @Test
    public void smoke() {
        try (Secp256k1 secp = Secp256k1.getByName("bouncy-castle")) {
            P256K1KeyPair keypair = secp.ecKeyPairCreate();
            assertNotNull(keypair);
        }
    }
}
