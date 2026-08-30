/*
 * Copyright by the original author or authors.
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
package org.bitcoinj.tools;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;

/**
 * List <b>bitcoinj</b>-related Cryptography {@link java.security.Provider}s found in the JDK or in Bouncy Castle (if Bouncy Castle
 * is on the classpath.)
 * <p>
 * Note that this list does not correspond to what the current version of <b>bitcoinj<b> actually uses.
 */
public class ListCryptoProviders {
    static final String BC_CLASS = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    static final String BC_NAME  = "BC";

    static final String ECDSA_SIG_ALGO = "SHA256withECDSA";
    static final List<String> BITCOIN_ALGOS = List.of(
            "MessageDigest.SHA-256",
            "MessageDigest.RIPEMD160",
            "MessageDigest.SHA3-256",
            "Mac.HmacSHA512",
            "SecretKeyFactory.PBKDF2WithHmacSHA512",
            "SecretKeyFactory.SCRYPT",
            "Cipher.AES"
    );
    static final String ECDSA_CURVE = "secp256k1";
    static final String ECDSA_OID = "1.3.132.0.10";   // same curve, alternate name

    public static void main(String[] args) {
        System.out.println("Searching for bitcoinj-related Java Cryptography Providers.");
        System.out.println("(Note that this is not a list of what the current version of bitcoinj actually uses.)\n");

        if (installBC()) {
            System.out.println("Bouncy Castle was found on classpath and installed.\n");
        }

        printEcdsaProviders();

        for (String algo : BITCOIN_ALGOS) {
            System.out.println(algo + ":");
            printProviders(algo);
            System.out.println("\n");
        }
    }

    static void printProviders(String algoName) {
        for (Provider p : listProviders(algoName)) {
            System.out.printf(" • %-12s %-8s %s%n", p.getName(), p.getVersionStr(), shortenInfo(p.getInfo()));
        }
    }

    static List<Provider> listProviders(String algoName) {
        Provider[] providerArray = Security.getProviders(algoName);
        return providerArray != null ? Arrays.asList(providerArray) : List.of();
    }

    static void  printEcdsaProviders() {
        Provider[] candidates = Security.getProviders("Signature." + ECDSA_SIG_ALGO);
        if (candidates == null) {
            System.out.println("No ECDSA at all.");
            return;
        }

        System.out.println("Signature." + ECDSA_SIG_ALGO + ":");
        for (Provider p : candidates) {
            boolean byName = ecdsaWorks(p, ECDSA_CURVE);
            boolean byOid  = byName || ecdsaWorks(p, ECDSA_OID);
            System.out.printf(" • %-12s %-8s %-40s  %s=%b\n",
                    p.getName(), p.getVersionStr(), shortenInfo(p.getInfo()), ECDSA_CURVE, byName || byOid);
        }
        System.out.println("\n");
    }

    static boolean installBC() {
        if (Security.getProvider(BC_NAME) != null) {
            return true;
        } else try {
            //Provider provider = (Provider) Class.forName(BC_CLASS).getDeclaredConstructor().newInstance();
            Provider provider = Class.forName(BC_CLASS).asSubclass(Provider.class).getDeclaredConstructor().newInstance();
            Security.addProvider(provider);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        } catch (ReflectiveOperationException | SecurityException e) {
            throw new IllegalStateException("Bouncy Castle is present but could not be registered", e);
        }
    }

    static boolean ecdsaWorks(Provider p, String curveName) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", p);
            kpg.initialize(new ECGenParameterSpec(curveName));
            KeyPair kp = kpg.generateKeyPair();

            byte[] msg = "smoke test".getBytes(StandardCharsets.UTF_8);

            Signature signer = Signature.getInstance(ECDSA_SIG_ALGO, p);
            signer.initSign(kp.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance(ECDSA_SIG_ALGO, p);
            verifier.initVerify(kp.getPublic());
            verifier.update(msg);
            return verifier.verify(sig);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    static String shortenInfo(String info) {
        String first = info.split(" ", 2)[0];
        return switch (first) {
            case "SUN", "SunJCE" -> first;
            default -> info;
        };
    }
}
