package org.bitcoinj.crypto.utils;

import org.bitcoinj.base.LegacyAddress;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.base.SegwitAddress;
import org.bitcoinj.crypto.internal.CryptoUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SignatureException;
import java.util.Arrays;

/**
 * Small utility class for verifying signatures of text messages created with
 * Bitcoin addresses (more precisely: with the private key of Bitcoin addresses).
 * Supports verifying of signatures created with:<ul>
 *     <li>P2PKH addresses (old legacy 1… addresses)</li>
 *     <li>P2WPKH addresses (native segwit v0 addresses, aka bc1q… addresses)</li>
 *     <li>P2SH-P2WPKH addresses (segwit wrapped into P2SH, aka legacy segwit addresses, like 3…)</li>
 * </ul>
 */
public class MessageVerifyUtils {

    private MessageVerifyUtils() {}

    private static final Logger log = LoggerFactory.getLogger(MessageVerifyUtils.class);
    public static final String SIGNATURE_FAILED_ERROR_MESSAGE = "Signature did not match for message";

    /**
     * Verifies messages signed with private keys of Bitcoin addresses.
     *
     * @param address         bitcoin address used to create the signature
     * @param message         message which has been signed
     * @param signatureBase64 signature as base64 encoded string
     * @throws SignatureException if the signature does not match the message and the address
     */
    public static void verifyMessage(final Address address,
                                     final String message,
                                     final String signatureBase64) throws SignatureException {
        try {
            final ScriptType scriptType = address.getOutputScriptType();

            switch (scriptType) {
                case P2PKH:
                case P2WPKH:
                    comparePubKeyHash(address, message, signatureBase64);
                    break;
                case P2SH:
                    compareP2SHScriptHashDerivedFromPubKey((LegacyAddress) address, message, signatureBase64);
                    break;
                default:
                    throw new SignatureException(SIGNATURE_FAILED_ERROR_MESSAGE);
            }

        } catch (final SignatureException se) {
            throw se;
        } catch (final Exception e) {
            log.warn("verifying of message signature failed with exception", e);
            throw new SignatureException(SIGNATURE_FAILED_ERROR_MESSAGE);
        }
    }

    private static void comparePubKeyHash(final Address address,
                                          final String message,
                                          final String signatureBase64) throws SignatureException {

        // Message signing/verification in this form is not supported for Taproot addresses
        // (Taproot uses Schnorr signatures, which - unlike ECDSA - do not support key recovery.)
        // A new message signing format is currently in work in BIP 322 that can verify signatures
        // from all types of addresses, including scripts, multisig, and Taproot.
        // It is currently a draft.
        if (address instanceof SegwitAddress) {
            if (((SegwitAddress) address).getWitnessVersion() > 0) {
                throw new SignatureException("Message verification currently only supports segwit version 0");
            }
        }

        final byte[] pubKeyHashFromSignature = ECKey.signedMessageToKey(message, signatureBase64).getPubKeyHash();
        final byte[] pubKeyHashFromAddress = address.getHash();

        if (!Arrays.equals(pubKeyHashFromAddress, pubKeyHashFromSignature)) {
            throw new SignatureException(SIGNATURE_FAILED_ERROR_MESSAGE);
        }
    }

    private static void compareP2SHScriptHashDerivedFromPubKey(final LegacyAddress address,
                                                               final String message,
                                                               final String signatureBase64) throws SignatureException {

        final byte[] pubKeyHashFromSignature = ECKey.signedMessageToKey(message, signatureBase64).getPubKeyHash();

        // in case of P2SH addresses the address doesn't contain a pubKeyHash, but
        // instead the hash of a script, to be used in a scriptPubKey like this:
        // > OP_HASH160 <20-byte-script-hash> OP_EQUAL
        // Here we get this "<20-byte-script-hash>":
        final byte[] scriptHashFromAddress = address.getHash();

        // The script whose hash is embedded in a P2SH-P2WPKH address is the
        // scriptPubKey of P2WPKH (see BIP 141):
        // > 0x00 OP_PUSH_20 <20-byte-pub-key-hash>
        // (the leading 0x00 is the witness program version byte)
        // So to be able to compare this with the recovered pubKeyHash, we need to
        // wrap the recovered pubKeyHash from the signature in the same type of script:
        final byte[] segwitScriptFromSignaturePubKey = wrapPubKeyHashInSegwitScript(pubKeyHashFromSignature);

        // and as in a P2SH address only the hash of the script is contained, we also hash this script before comparing:
        final byte[] scriptHashDerivedFromSig = CryptoUtils.sha256hash160(segwitScriptFromSignaturePubKey);

        if (!Arrays.equals(scriptHashFromAddress, scriptHashDerivedFromSig)) {
            throw new SignatureException(SIGNATURE_FAILED_ERROR_MESSAGE);
        }
    }

    /**
     * Returns "scriptPubKey" as it's used in BIP 141 P2WPKH addresses: 0x0014{20-byte-key-hash}
     *
     * @return (0x00 | 0x14 | pubKeyHash)
     * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#P2WPKH">BIP 141</a>
     */
    private static byte[] wrapPubKeyHashInSegwitScript(final byte[] pubKeyHash) {
        // According to BIP 141 the scriptPubkey for Segwit (P2WPKH) is prefixed with: 0x00 0x14
        // see BIP 141 (https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wpkh)

        // 0x00 indicates witness version 0
        // 0x14 is OP_PUSH_20, pushes the next 20 bytes (=length of the pubkeyHash) on the stack
        // (it's safe to hardcode version 0 here, as P2SH-wrapping is only defined for segwit version 0)
        final byte[] scriptPubKeyPrefix = {0x00, 0x14};
        return ByteUtils.concat(scriptPubKeyPrefix, pubKeyHash);
    }
}
