/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.core.bip47;

import org.bitcoinj.core.Sha256Hash;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.kits.BIP47AppKit;
import org.bitcoinj.wallet.bip47.NotSecp256k1Exception;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import static org.bitcoinj.utils.BIP47Util.getReceiveAddress;

public class BIP47Channel {
    private static final String TAG = "BIP47Channel";

    private static final int STATUS_NOT_SENT = -1;
    private static final int STATUS_SENT_CFM = 1;

    private static final int LOOKAHEAD = 10;

    private String paymentCode;
    private String label = "";
    private List<BIP47Address> incomingAddresses = new ArrayList<>();
    private List<String> outgoingAddresses = new ArrayList<>();
    private int status = STATUS_NOT_SENT;
    private int currentOutgoingIndex = 0;
    private int currentIncomingIndex = -1;
    private Sha256Hash ntxHash;

    private static final Logger log = LoggerFactory.getLogger(BIP47Channel.class);
    public BIP47Channel() {}

    public BIP47Channel(String paymentCode) {
        this.paymentCode = paymentCode;
    }

    public BIP47Channel(String paymentCode, String label) {
        this(paymentCode);
        this.label = label;
    }

    public String getPaymentCode() {
        return paymentCode;
    }

    public void setPaymentCode(String pc) {
        paymentCode = pc;
    }

    public List<BIP47Address> getIncomingAddresses() {
        return incomingAddresses;
    }

    public int getCurrentIncomingIndex() {
        return currentIncomingIndex;
    }

    public void generateKeys(BIP47AppKit wallet) throws NotSecp256k1Exception, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        for (int i = 0; i < LOOKAHEAD; i++) {
            ECKey key = getReceiveAddress(wallet, paymentCode, i).getReceiveECKey();
            Address address = wallet.getAddressOfKey(key);

            log.debug("New address generated");
            log.debug(address.toString());
            wallet.importKey(key);
            incomingAddresses.add(i, new BIP47Address(address.toString(), i));
        }

        currentIncomingIndex = LOOKAHEAD - 1;
    }

    public BIP47Address getIncomingAddress(String address) {
        for (BIP47Address bip47Address: incomingAddresses) {
            if (bip47Address.getAddress().equals(address)) {
                return bip47Address;
            }
        }
        return null;
    }

    public void addNewIncomingAddress(String newAddress, int nextIndex) {
        incomingAddresses.add(nextIndex, new BIP47Address(newAddress, nextIndex));
        currentIncomingIndex = nextIndex;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String l) {
        label = l;
    }

    public List<String> getOutgoingAddresses() {
        return outgoingAddresses;
    }

    public boolean isNotificationTransactionSent() {
        return status == STATUS_SENT_CFM;
    }

    public void setStatusSent() {
        status = STATUS_SENT_CFM;
    }

    public int getCurrentOutgoingIndex() {
        return currentOutgoingIndex;
    }

    public void incrementOutgoingIndex() {
        currentOutgoingIndex++;
    }

    public void addAddressToOutgoingAddresses(String address) {
        outgoingAddresses.add(address);
    }

    public void setStatusNotSent() {
        status = STATUS_NOT_SENT;
    }

    public Sha256Hash getNtxHash() { return ntxHash; }

    public void setNtxHash(Sha256Hash ntxHash) {
        this.ntxHash = ntxHash;
    }
}
