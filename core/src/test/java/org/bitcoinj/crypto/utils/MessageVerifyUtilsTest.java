package org.bitcoinj.crypto.utils;

import org.bitcoinj.base.AddressParser;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class MessageVerifyUtilsTest {

    @Parameterized.Parameters
    public static Collection<TestVector> testVectors() {
        return Arrays.asList(
                // testvectors from ECKeyTest.java:
                new TestVector(MainNetParams.get(), "14YPSNPi6NSXnUxtPAsyJSuw3pv7AU3Cag", "hello", "HxNZdo6ggZ41hd3mM3gfJRqOQPZYcO8z8qdX2BwmpbF11CaOQV+QiZGGQxaYOncKoNW61oRuSMMF8udfK54XqI8=", true, "P2PKH address from compressed public key"),
                new TestVector(MainNetParams.get(), "1C6SjmutxV21sPdqQAWLJbvznfyCoU2zWc", "message signed using an p2pkh address derived from an uncompressed public key", "HDoME2gqLJApQTOLnce4J7BZcO1yIxUSP6tdKIUBLO99E+BH3uABshRoFzIdVYZo16zpAGtiHq8Xq9YbswDVR1M=", true, "P2PKH address from uncompressed public key"),
                new TestVector(MainNetParams.get(), "bc1qvcl0z7f25sf2u8up5wplk7arwclghh7de8fy6l", "This msg was signed with a native SegWit v0 address, the signature header byte therefore is in the range 39-42 (according to BIP 137).", "KH4/rrraZsPwuuW6pSKVnZVdZXmzLPBOPSS9zz6QLZnTGhO2mHFAs53QLPp94Hahz7kTgNiO6VYZpehMbNHIvNA=", true, "signature from native Segwit (bech32) address"),
                new TestVector(MainNetParams.get(), "3HnHC8dJCqixUBFNYXdz2LFXQwvAkkTR3m", "This message was signed with a P2SH-P2WPKH address, the signature header byte therefore is in the range 35-38 (according to BIP 137).", "I6CwPW9ErVV8SphnQbHnOfYcwcqMdJaZRkym5QHzykpzVw38SrftZFaWoqMl+pvJ92hOyj8PjDOQOT2hDXtk5V0=", true, "signature from a P2WPKH-wrapped-into-P2SH type address"),
                // collection of testvectors found in other projects or online
                new TestVector(MainNetParams.get(), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM", "vires is numeris", "G8JawPtQOrybrSP1WHQnQPr67B9S3qrxBrl1mlzoTJOSHEpmnF7D3+t+LX0Xei9J20B5AIdPbeL3AaTBZ4N3bY0=", true, "uncompressed public key"),
                new TestVector(MainNetParams.get(), "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs", "vires is numeris", "H8JawPtQOrybrSP1WHQnQPr67B9S3qrxBrl1mlzoTJOSHEpmnF7D3+t+LX0Xei9J20B5AIdPbeL3AaTBZ4N3bY0=", true, "compressed public key"),
                new TestVector(MainNetParams.get(), "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN", "vires is numeris", "JF8nHqFr3K2UKYahhX3soVeoW8W1ECNbr0wfck7lzyXjCS5Q16Ek45zyBuy1Fiy9sTPKVgsqqOuPvbycuVSSVl8=", true, "legacy segwit (always compressed pubkey)"),
                new TestVector(MainNetParams.get(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "vires is numeris", "KF8nHqFr3K2UKYahhX3soVeoW8W1ECNbr0wfck7lzyXjCS5Q16Ek45zyBuy1Fiy9sTPKVgsqqOuPvbycuVSSVl8=", true, "segwit (always compressed pubkey)"),
                new TestVector(MainNetParams.get(), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM", "foobar", "G8JawPtQOrybrSP1WHQnQPr67B9S3qrxBrl1mlzoTJOSHEpmnF7D3+t+LX0Xei9J20B5AIdPbeL3AaTBZ4N3bY0=", false, "fail for the wrong message"),
                new TestVector(MainNetParams.get(), "1111111111111111111114oLvT2", "vires is numeris", "H8JawPtQOrybrSP1WHQnQPr67B9S3qrxBrl1mlzoTJOSHEpmnF7D3+t+LX0Xei9J20B5AIdPbeL3AaTBZ4N3bY0=", false, "fail for the wrong address"),
                new TestVector(MainNetParams.get(), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM", "vires is numeris", "H8JawPtQOrybrSP1WHQnQPr67B9S3qrxBrl1mlzoTJOSHEpmnF7D3+t+LX0Xei9J20B5AIdPbeL3AaTBZ4N3bY0=", false, "should fail because -> uncompressed address,but compressed flag in signature"),
                new TestVector(MainNetParams.get(), "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs", "vires is numeris", "G8JawPtQOrybrSP1WHQnQPr67B9S3qrxBrl1mlzoTJOSHEpmnF7D3+t+LX0Xei9J20B5AIdPbeL3AaTBZ4N3bY0=", false, "should fail because -> compressed address,but uncompressed flag in signature"),
                new TestVector(MainNetParams.get(), "bc1q6nmtgxgfx2up7zuuydglme8fydugkh7jsrnz7f", "12345678", "J4cRzK+gDAJfGddCKB9EAHA2rOnxCZXowwGO/Zu4AmMvONsAE0b8vTez6pvMYl+gTjyn9AJv7PieFrGVTSWKK4M=", true, "shouldValidate_P2WPKH"),
                new TestVector(MainNetParams.get(), "bc1qp2ltq2tgsjav3rq3lt38lzfnpzewv8fcharjyk", "1113875075", "HzXKbcRCe5By+a/7CRh0QMd6B2SdnDKcNKzieBRCkYtzCrBquTRZO49iDmwWqiAMphlpqmVQUxmHLSe0Y9GGysQ=", true, "shouldValidate_P2WPKH_GeneratedByElectrum"),
                new TestVector(MainNetParams.get(), "33wW4GTkzMhgS3QvTP5K7jKY7i8zuzwqKg", "12345678", "I6N4ZR5jYHLO9HgpGjlWF87TU91cRELtg84TZmEJQnkGQ9XGNQiGd2MB+XKkbzPVpgbvqrgvbVV+n81X1m52TYI=", true, "shouldValidate P2SH-P2WPKH"),
                new TestVector(MainNetParams.get(), "1EqTxusZzKmMhHhCevCmh7fWMVf8PuD6TT", "12345678", "HxeBIxrx4VFWCEqMEiTlK/PVjqYBrkgty1ileKE3bteSPUDIGJOMOvjhyG/+WRAgT+mTEWtWpUaFmFktoKuXGmA=", true, "shouldValidate-P2PKH"),
                new TestVector(MainNetParams.get(), "14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e", "VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!", "IF/3lcKa73U4+LO9suit0NByKtYwoUC2rv1QSlqJXL2GfLsAmBr8UO3QOYIR6NfDBLuO+kYRgbwK+mfqSnIKie0=", true, "testcase from trezor"),
                new TestVector(MainNetParams.get(), "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T", "This is an example of a signed message.", "G6d+Aanhe6FYuWLP718T3+1nb/wrS62iTlj3hEWLUrl0IUcNAB1T1YgM9eEOdvAr4+gL8h4YOYy9QejDtK90yMI=", true, "test vector from bitcoinjs-message"),
                new TestVector(MainNetParams.get(), "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T", "This is an example of a signed message.", "G6d+Aanhe6FYuWLP718T3+1nb/wrS62iTlj3hEWLUrl0IUcNAB1T1YgM9eEOdvAr4+gL8h4YOYy9QejDtK90yAA=", false, "test vector from bitcoinjs-message"),
                new TestVector(MainNetParams.get(), "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T", "This is an example of a signed message!", "G6d+Aanhe6FYuWLP718T3+1nb/wrS62iTlj3hEWLUrl0IUcNAB1T1YgM9eEOdvAr4+gL8h4YOYy9QejDtK90yMI=", false, "test vector from bitcoinjs-message"),
                new TestVector(MainNetParams.get(), "1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8", "This is an example of a signed message.", "H0Tj5GH3yp9XxHLOGighTfHeHa3vtlUaMtGQe4DHTVofv9baq6Et2MsGaZzj9pQfvg85V7WALRMHYYEEbnQeqq8=", true, "test vector from bitcoinjs-message"),
                new TestVector(MainNetParams.get(), "1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8", "This is an example of a signed message.", "H0Tj5GH3yp9XxHLOGighTfHeHa3vtlUaMtGQe4DHTVofv9baq6Et2MsGaZzj9pQfvg85V7WALRMHYYEEbnQeqgA=", false, "test vector from bitcoinjs-message"),
                new TestVector(MainNetParams.get(), "1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8", "This is an example of a signed message!", "H0Tj5GH3yp9XxHLOGighTfHeHa3vtlUaMtGQe4DHTVofv9baq6Et2MsGaZzj9pQfvg85V7WALRMHYYEEbnQeqq8=", false, "test vector from bitcoinjs-message"),
                new TestVector(MainNetParams.get(), "14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e", "This is an example of a signed message.", "IJ4j7fDk5H/x3sJ/Ms14xQ507wGO6Kat81rhfHqbDdlvSLST/X26sD77b0OcY4PJUjs7vF8afRWKavkKsVTpvoA=", true, "test vector from bitcoinjs-message"),
                new TestVector(MainNetParams.get(), "14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e", "This is an example of a signed message.", "IJ4j7fDk5H/x3sJ/Ms14xQ507wGO6Kat81rhfHqbDdlvSLST/X26sD77b0OcY4PJUjs7vF8afRWKavkKsVTpvgA=", false, "test vector from bitcoinjs-message"),
                new TestVector(MainNetParams.get(), "14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e", "This is an example of a signed message!", "IJ4j7fDk5H/x3sJ/Ms14xQ507wGO6Kat81rhfHqbDdlvSLST/X26sD77b0OcY4PJUjs7vF8afRWKavkKsVTpvoA=", false, "test vector from bitcoinjs-message"),
                new TestVector(MainNetParams.get(), "1KzXE97kV7DrpxCViCN3HbGbiKhzzPM7TQ", "žluťoučký kůň úpěl ďábelské ódy", "HMaU8PI5Ad/jYDeJFC82o/xYLQ1cDschXPLM1kHk43IoUE89TcPuoou9v12ifEnUY1wJcATZ8ih1DM2Dao4UYMA=", true, "test vector from bitcoinjs-message"),
                new TestVector(MainNetParams.get(), "3CwYaeWxhpXXiHue3ciQez1DLaTEAXcKa1", "This is an example of a signed message.", "JJ4j7fDk5H/x3sJ/Ms14xQ507wGO6Kat81rhfHqbDdlvSLST/X26sD77b0OcY4PJUjs7vF8afRWKavkKsVTpvoA=", true, "test vector from bitcoinjs-message"),
                new TestVector(MainNetParams.get(), "3CwYaeWxhpXXiHue3ciQez1DLaTEAXcKa1", "VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!", "JF/3lcKa73U4+LO9suit0NByKtYwoUC2rv1QSlqJXL2GfLsAmBr8UO3QOYIR6NfDBLuO+kYRgbwK+mfqSnIKie0=", true, "test case from trezor"),
                new TestVector(MainNetParams.get(), "3CwYaeWxhpXXiHue3ciQez1DLaTEAXcKa1", "Příšerně žluťoučký kůň úpěl ďábelské ódy zákeřný učeň běží podél zóny úlů", "JNDsAu2NqN8j5/6eaA54Z8wpAxL+HJcHSdgwbdrRoe2kHGp3GxPUld0iWxOwqdD5FamE7j0HA/kih7+ACfu599Y=", true, ""),
                new TestVector(MainNetParams.get(), "bc1qyjjkmdpu7metqt5r36jf872a34syws33s82q2j", "This is an example of a signed message.", "KJ4j7fDk5H/x3sJ/Ms14xQ507wGO6Kat81rhfHqbDdlvSLST/X26sD77b0OcY4PJUjs7vF8afRWKavkKsVTpvoA=", true, ""),
                new TestVector(MainNetParams.get(), "bc1qyjjkmdpu7metqt5r36jf872a34syws33s82q2j", "VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!VeryLongMessage!", "KF/3lcKa73U4+LO9suit0NByKtYwoUC2rv1QSlqJXL2GfLsAmBr8UO3QOYIR6NfDBLuO+kYRgbwK+mfqSnIKie0=", true, "test case from trezor"),
                new TestVector(MainNetParams.get(), "bc1qyjjkmdpu7metqt5r36jf872a34syws33s82q2j", "Příšerně žluťoučký kůň úpěl ďábelské ódy zákeřný učeň běží podél zóny úlů", "KNDsAu2NqN8j5/6eaA54Z8wpAxL+HJcHSdgwbdrRoe2kHGp3GxPUld0iWxOwqdD5FamE7j0HA/kih7+ACfu599Y=", true, "test case from trezor"),
                new TestVector(MainNetParams.get(), "bc1qr98j5exfpgn3g6tup064sjtr8hqf4hwesg8x2n", "⚡️⚡️⚡️  We löööve Lightning. This signature was created with Electrum 4.2.1 and a P2PWKH address (native segwit).", "ICD+yhkWDgBMHLhLwFkKC7ndcc2STRSCWApKDQDBhuuCd9AjigggCMGyrZvXNWBXn650WB9uncaq22adCyYYNQQ=", true, "Native Segwit generated with Electrum 4.2.1"),
                new TestVector(MainNetParams.get(), "19rK6PL7KUQNk2Z9dGRGjnhDd6QUA5QXwa", "⚡️⚡️⚡️🤯🥳🥸  We still lööve Lightning.  :) This signature was created with Electrum 4.2.1 and a compressed P2PKH address (legacy 1.. address).", "HyKVgA7lPUXt50BqMhRYrLQNiP3hVOiU9SavIzopactCUWcy9NVcIb/FvmknKQQpeH3A38DZv7mHM/uSQPXhWf8=", true, "Compressed P2PKH (legacy address) sig generated with Electrum 4.2.1"),
                new TestVector(MainNetParams.get(), "1FizteKkFBDvqYX5FKSqaXXsoieFv8YXC3", "😶‍🌫️🧐🤓  Old and legäcy, this signature was created with Electrum 4.2.1 and a UNCOMPRESSED P2PKH address (1er.. address). Uncompressed is soooo retro... 🙈", "HBLk5Jy5WzCGBpzrNQxABbJ4lT34f12uwMgmg4TSwIAXWQZ2FvLXHib1Vl9n9TmFWIdwGiHuNtpv+q0a7sHOT5U=", true, "Uncompressed P2PKH (legacy address) sig generated with Electrum 4.2.1"),
                new TestVector(MainNetParams.get(), "383jWSXohdSkpLKQPV2a91xqqJ83ZkGrA4", "🥸🤮😻 Legäcy segwit, wrapped into P2SH, compressed, this signature was created with Electrum 4.2.1 P2SH-P2WPKH address (3er.. legacy segwit address).", "H3B3EvJKTvVSjr8o7ZssUfeoEfauqj3jRIs0Js/QCsQjN230pIM2C3GMqmDDP+Uo+OB6OZaXiVrAkuSmJ0iABvU=", true, "Uncompressed P2PKH (legacy address) sig generated with Electrum 4.2.1"),
                new TestVector(MainNetParams.get(), "bc1qzeacswvlulg0jngad9gmtkvdp9lwum42wwzdu5", "Hello", "HxuuWQwjw0417fLV9L0kWbt7w9XOIWKhHMhjXhyXTczcSozGTXM4knqdISiYbbmqSRXqI5mNTWH9qkDoqZTpnPc=", true, "example from COLDCARD: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-July/020762.html"),
                new TestVector(MainNetParams.get(), "14YPSNPi6NSXnUxtPAsyJSuw3pv7AU3Cag", "hello", "HxNZdo6ggZ41hd3mM3gfJRqOQPZYcO8z8qdX2BwmpbF11CaOQV+QiZGGQxaYOncKoNW61oRuSMMF8udfK54XqI8=", true, "Testvector from bitcoinJ"),
                new TestVector(MainNetParams.get(), "17o6NDP6nemtm8ZundHEMbxmHsPGnVyggs", "聡中本", "H4c/RMMLsKJvxDk7uI2vt6qSbzyfvKGo+g8uNOsEhIKxWgzqZk547uI22fg5MX+jI17yvkB5qyizrO6DUJ/HfYw=", true, "another Testvector from bitcoinJ"),
                new TestVector(MainNetParams.get(), "1FbPLPR1XoufBQRPGd9JBLPbKLaGjbax5m", "Craig Steven Wright is a liar and a fraud. He doesn't have the keys used to sign this message.\n\nThe Lightning Network is a significant achievement. However, we need to continue work on improving on-chain capacity.\n\nUnfortunately, the solution is not to just change a constant in the code or to allow powerful participants to force out others.\n\nWe are all Satoshi", "G3SsgKMKAOiOaMzKSGqpKo5MFpt0biP9MbO5UkSl7VxRKcv6Uz+3mHsuEJn58lZlRksvazOKAtuMUMolg/hE9WI=", true, "publicly available signature from here: https://archive.ph/Z1oB8"),
                new TestVector(TestNet3Params.get(), "mirio8q3gtv7fhdnmb3TpZ4EuafdzSs7zL", "This is an example of a signed message.", "IJ4j7fDk5H/x3sJ/Ms14xQ507wGO6Kat81rhfHqbDdlvSLST/X26sD77b0OcY4PJUjs7vF8afRWKavkKsVTpvoA=", true, "Testnet test vector from Trezor repo")
        );
    }

    private final TestVector testVector;

    public MessageVerifyUtilsTest(TestVector testVector) {
        this.testVector = testVector;
    }

    @Test
    public void testMessageSignatureVerification() {
        final AddressParser addressParser = AddressParser.getDefault(testVector.networkParameters.network());
        try {
            MessageVerifyUtils.verifyMessage(
                    addressParser.parseAddress(testVector.address),
                    testVector.message,
                    testVector.signature
            );
            if (!testVector.shouldVerify) {
                fail("verification should have failed, but succeed: " + testVector + "\n");
            }
        } catch (Exception e) {
            if (testVector.shouldVerify) {
                fail("verification should have succeeded, but failed: " + testVector + "\n");
            }
        }
    }

    private static class TestVector {
        private final NetworkParameters networkParameters;
        private final String address;
        private final String message;
        private final String signature;
        private final boolean shouldVerify;
        private final String comment;

        public TestVector(NetworkParameters network, String address, String message, String signature, boolean shouldVerify, String comment) {
            this.networkParameters = network;
            this.address = address;
            this.message = message;
            this.signature = signature;
            this.shouldVerify = shouldVerify;
            this.comment = comment;
        }

        @Override
        public String toString() {
            return "TestVector{" +
                    "address='" + address + '\'' +
                    ", message='" + message + '\'' +
                    ", signature='" + signature + '\'' +
                    ", shouldVerify=" + shouldVerify +
                    ", comment='" + comment + '\'' +
                    '}';
        }
    }
}
