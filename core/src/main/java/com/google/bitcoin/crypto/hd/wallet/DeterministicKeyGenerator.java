package com.google.bitcoin.crypto.hd.wallet;

import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.crypto.hd.ChildNumber;
import com.google.bitcoin.crypto.hd.DeterministicHierarchy;
import com.google.bitcoin.crypto.hd.ExtendedHierarchicKey;
import com.google.common.collect.ImmutableList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * @author Matija Mazi <br/>
 *
 * A WalletKeyGenerator, used by Wallet, that uses BIP32 for key generation: internal deterministic chain for change
 * keys and external chain for receiving keys.
 */
public class DeterministicKeyGenerator implements WalletKeyGenerator, Serializable {
    private static final Logger log = LoggerFactory.getLogger(DeterministicKeyGenerator.class);

    public static final boolean PRIVATE_DERIVATION = true;

    public static final ChildNumber EXTERNAL_CHAIN = new ChildNumber(0, PRIVATE_DERIVATION);
    public static final ChildNumber INTERNAL_CHAIN = new ChildNumber(1, PRIVATE_DERIVATION);

    //    private final NetworkParameters params;
    private final DeterministicHierarchy hierarchy;
    private final ImmutableList<ChildNumber> externalChainRootPath;
    private final ImmutableList<ChildNumber> internalChainRootPath;

    public DeterministicKeyGenerator(ExtendedHierarchicKey rootKey) {
        log.debug("DeterministicKeyGenerator.DeterministicKeyGenerator");
        long start = System.currentTimeMillis();
//        this.params = params;
        hierarchy = new DeterministicHierarchy(rootKey);
        externalChainRootPath = hierarchy.deriveChild(rootKey.getChildNumberPath(), false, false, EXTERNAL_CHAIN).getChildNumberPath();
        internalChainRootPath = hierarchy.deriveChild(rootKey.getChildNumberPath(), false, false, INTERNAL_CHAIN).getChildNumberPath();
        log.debug("DKG constructor took {}", System.currentTimeMillis() - start);
    }

    public ExtendedHierarchicKey nextExternal() {
        log.debug("DeterministicKeyGenerator.nextExternal");
        return hierarchy.deriveNextChild(externalChainRootPath, false, false, PRIVATE_DERIVATION);
    }

    public ExtendedHierarchicKey nextInternal() {
        log.debug("DeterministicKeyGenerator.nextInternal");
        return hierarchy.deriveNextChild(internalChainRootPath, false, false, PRIVATE_DERIVATION);
    }

    @Override
    public ECKey nextReceivingKey() {
        return nextExternal().toECKey();
    }

    @Override
    public ECKey nextChangeKey(ArrayList<ECKey> keychain) {
        return nextInternal().toECKey();
    }

    /*
    private Address nextExternalAddress() {
        return nextExternal().toECKey().toAddress(getParams());
    }

    private Address nextInternalAddress() {
        return nextInternal().toECKey().toAddress(getParams());
    }

    synchronized Address getChangeAddress() {
        return nextInternalAddress();
    }

    public ExtendedHierarchicKey getRootKey() {
        return hierarchy.getRootKey();
    }

    public NetworkParameters getParams() {
        return params;
    }
*/
}

