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

package org.bitcoinj.crypto;

import org.bitcoinj.base.Base58;
import org.bitcoinj.base.Bech32;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.NetworkParameters;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bitcoin Output Script Descriptor.
 * <p>
 * Bitcoin Output Script Descriptors are defined in a series of BIPs (see references below) as "a simple language which can be used to describe collections of output scripts". They are meant to improve interoperability
 * when backing up or restoring wallets, exporting information for creating watch-only wallets, and similar use cases.
 * <p>
 * Preliminary implementation is essentially a typed wrapper for a {@link String}, but in the future might have richer functionality.
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki">BIP 380: Output Script Descriptors General Operation</a>
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0381.mediawiki">BIP 381: Non-Segwit Output Script Descriptors</a>
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0382.mediawiki">BIP 382: Segwit Output Script Descriptors</a>
 * @see <a href="https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md">Support for Output Descriptors in Bitcoin Core</a>
 */
public interface OutputDescriptor {
    /**
     * @return the output descriptor as a string
     */
    String toString();

    /**
     * Simple, preliminary implementation of {@code Descriptor} for bitcoinj {@code DeterministicKeyChain}
     * <p>
     * Either this should not be an inner class because it has dependencies on the crypto package, or
     * we can migrate some of that functionality to a `base` package and minimize the dependencies.
     */
    class HDKeychainOutputDescriptor implements OutputDescriptor {
        private final ScriptType scriptType;
        private final DeterministicKey accountKey;
        private final String descriptor;

        public HDKeychainOutputDescriptor(ScriptType scriptType, String xpub, HDPath path, int fingerprint) {
            this.scriptType = scriptType;
            this.accountKey = deserializeBase58(xpub);
            String func = scriptType.id();
            //String pathString = path.toString().substring(1).replace("H", "'");
            // TODO: Handle [Hh'] on both input and output
            String pathString = path.toString().substring(1);
            descriptor = String.format("%s([%x%s]%s%s)", func, fingerprint, pathString, xpub, "");
        }

        public HDKeychainOutputDescriptor(ScriptType scriptType, String xpub) {
            this.scriptType = scriptType;
            this.accountKey = deserializeBase58(xpub);
            String func = scriptType.id();
            descriptor = String.format("%s(%s%s)", func, xpub, "");
        }


        public static OutputDescriptor of(ScriptType scriptType, String xpub, HDPath path, int fingerprint) {
            return new HDKeychainOutputDescriptor(scriptType, xpub, path, fingerprint);
        }

        public static OutputDescriptor of(ScriptType scriptType, String xpub) {
            return new HDKeychainOutputDescriptor(scriptType, xpub);
        }

        @Override
        public String toString() {
            return descriptor;
        }

        public ScriptType scriptType() {
            return scriptType;
        }

        public boolean isPublicKey() {
            return !accountKey.hasPrivKey();
        }

        public DeterministicKey accountKey() {
            return accountKey;
        }

        static final String scriptPattern = "(pkh|wpkh)";
        static final String fingerPrintPattern = "[A-Fa-f0-9]{8}";
        static final String acctPathPattern = "(/[0-9]{1,4}[hH']?)*";
        static final String xpubPattern = String.format("(x|t)pub[%s]{20,200}", Base58.CHARSET);
        static final String childPathPattern = "(/[0-9]{1,4}[hH']?|)*(/\\*)?";
        static final String checksumPattern = String.format("[%s]{8}", Bech32.CHARSET);

        static final String scriptCapture = namedCapture("script", scriptPattern);
        static final String fingerprintCapture = namedCapture("fingerprint", fingerPrintPattern);
        static final String acctPathCapture = namedCapture("acctpath", acctPathPattern);
        static final String xpubCapture = namedCapture("xpub", xpubPattern);
        static final String childPathCapture = namedCapture("childpath", childPathPattern);
        static final String checksumCapture = namedCapture("checksum", checksumPattern);

        /**
         * Format string for assembling the component named captures into a regex that can parse the subset
         * of Output Descriptors that match bitcoinj {@code DeterministicKeyChain}s.
         * <p>
         * Each {@code %s} should be substituted with a named group capture. See {@link #hdKeychainRegex}
         */
        static final String hdKeychainRegexFormat = "%s\\((\\[%s%s?\\])?%s%s?\\)(#%s)?";
        static final String hdKeychainRegex = String.format(hdKeychainRegexFormat, scriptCapture, fingerprintCapture, acctPathCapture, xpubCapture, childPathCapture, checksumCapture);
        static final Pattern hdKeychainPattern = Pattern.compile(hdKeychainRegex);

        /**
         * Parse a {@code String} and return a {@code Descriptor}
         * TODO: Consider making this return a functional (monadic) result type before the next release
         * @param descriptorString A candidate descriptor string
         * @return a descriptor object if the string was valid
         * @throws IllegalArgumentException if the string was invalid
         */
        public static HDKeychainOutputDescriptor parse(String descriptorString) throws IllegalArgumentException {
            Matcher matcher = hdKeychainPattern.matcher(descriptorString);
            if (matcher.find()) {
                String scriptFunc = matcher.group("script");
                String fingerprint = matcher.group("fingerprint");
                String acctpath = matcher.group("acctpath");
                String xpub = matcher.group("xpub");
                String checksum = matcher.group("checksum");
                ScriptType scriptType = ScriptType.of(scriptFunc);
                if (acctpath != null && fingerprint != null) {
                    return new HDKeychainOutputDescriptor(scriptType, xpub, HDPath.parsePath(acctpath), Integer.parseInt(fingerprint, 16));
                } else {
                    return new HDKeychainOutputDescriptor(scriptType, xpub);
                }
            }
            else {
                throw new IllegalArgumentException("Invalid or unsupported descriptor");
            }
        }

        private static String namedCapture(String name, String pattern) {
            return String.format("(?<%s>%s)", name, pattern);
        }

        private static DeterministicKey deserializeBase58(String keyString) {
            BitcoinNetwork network = keyString.startsWith("x") ? BitcoinNetwork.MAINNET : BitcoinNetwork.TESTNET;
            return DeterministicKey.deserializeB58(keyString, NetworkParameters.of(network));
        }
    }
}
