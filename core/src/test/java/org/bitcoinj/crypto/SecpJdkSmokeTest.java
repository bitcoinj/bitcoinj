package org.bitcoinj.crypto;

import org.bitcoinj.secp256k1.api.Secp256k1;
import org.junit.Test;

/**
 *
 */
public class SecpJdkSmokeTest {
    @Test
    public void smoke() {
        try (Secp256k1 secp = Secp256k1.getByName("bouncy-castle")) {
            var keypair = secp.ecKeyPairCreate();
            System.out.println(keypair.getPublic().getFormat());
        }
    }
}
