package org.bitcoinj.wallet;

import org.bitcoinj.base.ScriptType;
import org.bitcoinj.crypto.OutputDescriptor;
import org.bitcoinj.base.Network;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.time.Instant;
import java.util.stream.Stream;

import static org.bitcoinj.base.ScriptType.P2PKH;
import static org.bitcoinj.base.ScriptType.P2WPKH;
import static org.bitcoinj.base.BitcoinNetwork.MAINNET;
import static org.bitcoinj.base.BitcoinNetwork.TESTNET;
import static org.bitcoinj.wallet.KeyChainGroupStructure.BIP32;
import static org.bitcoinj.wallet.KeyChainGroupStructure.BIP43;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test creation of output descriptors from deterministic keychains and creation of deterministic keychains from output descriptors
 */
public class DeterministicKeyChainDescriptorTest {
    // This mnemonic is used in the Blockchain Commons test vectors that you can
    // find here: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-015-account.md
    private static final String shieldMnemonic = "shield group erode awake lock sausage cash glare wave crew flame glove";
    private static final String pandaMnemonic = "panda diary marriage suffer basic glare surge auto scissors describe sell unique";

    @MethodSource("descriptorParams")
    @ParameterizedTest(name = "{3}, {4}, {0} generate descriptor {2}")
    void descriptorStringTest(String mnemonic, KeyChainGroupStructure structure, String expectedDescriptor, ScriptType scriptType,
                                  Network network) throws IOException, UnreadableWalletException {
        // When we create a keychain with parameterized structure, network, and scriptType
        DeterministicKeyChain chain = createChain(mnemonic, network, structure, scriptType);

        // Then the output descriptor is as expected
        assertEquals(expectedDescriptor, chain.outputDescriptorFor(network).toString());
    }

    @MethodSource("descriptorParams")
    @ParameterizedTest(name = "create chain {2}")
    void createChainFromDescriptorTest(String mnemonic, KeyChainGroupStructure structure, String descriptorString, ScriptType scriptType,
                              Network network) throws IOException, UnreadableWalletException {
        // When we create a keychain with parameterized structure, network, and scriptType
        OutputDescriptor.HDKeychainOutputDescriptor descriptor = OutputDescriptor.HDKeychainOutputDescriptor.parse(descriptorString);
        DeterministicKeyChain chain = DeterministicKeyChain.fromDescriptor(descriptor);

        assertNotNull(chain);
        assertEquals(chain.getOutputScriptType(), scriptType);
        assertEquals(chain.getKeyByPath(chain.getAccountPath()).serializePubB58(network), descriptor.accountKey().serializePubB58(network));

        // Then the output descriptor is as expected
        // We can't do this because we're losing the rootKey and accountPath, see https://github.com/bitcoinj/bitcoinj/issues/2474
        // assertEquals(descriptorString, chain.outputDescriptorFor(network).toString());
    }

    private static Stream<Arguments> descriptorParams() {
        // Two of these are actual "test vectors" from here:  https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-015-account.md
        // It would be nice to check the others against another implementation or add "test vectors" from elsewhere.
        return Stream.of(
            Arguments.of(shieldMnemonic, BIP43, "pkh([37b5eed4/44H/0H/0H]xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu)", P2PKH, MAINNET),   // BC Test Vector
            Arguments.of(shieldMnemonic, BIP43, "pkh([37b5eed4/44H/1H/0H]tpubDDdw9oYfrgtiChkHZkEYGqvqGqyg9gHjxTfbWKaPBdp67cTtxxsa4WXZczbSfhFiWH1VYddhfFAqqi2GBVcXB6q8mSJ5hpHUmPTKBZcjCXM)", P2PKH, TESTNET),
            Arguments.of(shieldMnemonic, BIP43, "wpkh([37b5eed4/84H/0H/0H]xpub6BkU445MSEBXbPjD3g2c2ch6mn8yy1SXXQUM7EwjgYiq6Wt1NDwDZ45npqWcV8uQC5oi2gHuVukoCoZZyT4HKq8EpotPMqGqxdZRuapCQ23)", P2WPKH, MAINNET), // BC Test Vector
            Arguments.of(shieldMnemonic, BIP43, "wpkh([37b5eed4/84H/1H/0H]tpubDDSaaAcCE5gxUitLcyTLfB2jNs7oVoeUNEBKA8DoXphtpTC9eXUPKDLECT3NVNqQweM5bmgQSBtTjjPcyX9vXXPEvziPq4BUAGGJ2Gy7X99)", P2WPKH, TESTNET),
            Arguments.of(pandaMnemonic, BIP43, "pkh([4df40cd9/44H/0H/0H]xpub6Ct7aoyW5Hf58xJsmpjhngM8Q5q46PsUZ7B97nSy24KSqy9jEDZkn4fYexV7wseRKTrd1GCs3YvKZKqtAJ31ZYhYe3nXBqaZsqw5ZVXUf2R)", P2PKH, MAINNET),
            Arguments.of(pandaMnemonic, BIP43, "pkh([4df40cd9/44H/1H/0H]tpubDDpSwdfCsfnYP8SH7YZvu1LK3BUMr3RQruCKTkKdtnHy2iBNJWn1CYvLwgskZxVNBV4KhicZ4FfgFCGjTwo4ATqdwoQcb5UjJ6ejaey5Ff8)", P2PKH, TESTNET),
            Arguments.of(pandaMnemonic, BIP43, "wpkh([4df40cd9/84H/0H/0H]xpub6CjyE3u2yWYTL53zCYnba9wLcTDMCbcf7zmpCxqjJ8R1ZeD74AmqguSv7zK1gPuCDRHrkBsp5AsVEEtH9KfhcWamjzbe9tq7vbsPhJ9RWXN)", P2WPKH, MAINNET),
            Arguments.of(pandaMnemonic, BIP43, "wpkh([4df40cd9/84H/1H/0H]tpubDD7xnGXSYaV1dFzCaMM3pMtpbKoqSesS3uvsqAfDfVYmu5owLj5tuXLrY1AesmkqoJRiT4yFaYPF6JP171vrgi2F6jdoMMGJZdaN5CryMGs)", P2WPKH, TESTNET),
            // Note: For BIP32 wallets the Network does not affect the path
            Arguments.of(pandaMnemonic, BIP32, "pkh([4df40cd9/0H]xpub68TjJfnePXHGSv472JtZMGzL4nwtvXPDvRM5gHeRK2kfRocjP9QVm3dWbh2EKWwhBmDi3vJuncYg6J4NpuT4mW1i4Wga8FPePhGomyHDps6)", P2PKH,  MAINNET),
            Arguments.of(pandaMnemonic, BIP32, "pkh([4df40cd9/0H]tpubD8qMpucL6oEiiiExUVseZCKhPv3YuutHU3wP2qhZewWZB6HSTNFauVJLqj71r1tvyfkcfVpnKiNinUYzDmJJewU187Rson3syesDY2nrwQ2)", P2PKH,  TESTNET),
            Arguments.of(pandaMnemonic, BIP32, "wpkh([4df40cd9/1H]xpub68TjJfnePXHGVDUewnGkwPBvpNEqKcwgxoyfPhACXm7MWsQ8d65WGoY6vgsaK174p8E3iR4cTriqhGmniHcN5SKe4C9EQKenj4TiuxXHtU9)", P2WPKH, MAINNET),
            Arguments.of(pandaMnemonic, BIP32, "wpkh([4df40cd9/1H]tpubD8qMpucL6oEim1fWPyFr9JXJ9VLVK1SkWSZxkFDLsfsFGA4qhJvbRFCwAixMqW4Jc2kxKzaUzxYtPTGQ79Tbxsmw7ntY5rK2K248fzD2rRT)", P2WPKH, TESTNET)
        );
    }

    // Create a deterministic keychain
    private static DeterministicKeyChain createChain(String mnemonic, Network network, KeyChainGroupStructure structure, ScriptType outputScriptType) throws IOException, UnreadableWalletException {
        DeterministicSeed seed = new DeterministicSeed(mnemonic, null, "", Instant.now().getEpochSecond());
       return DeterministicKeyChain.builder().seed(seed)
                .accountPath(structure.accountPathFor(outputScriptType, network))
                .outputScriptType(outputScriptType)
                .build();
    }
}
