package org.bitcoinj.testing;

import org.bitcoinj.core.Wallet;
import org.bitcoinj.core.WalletExtension;

import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;

public class FooWalletExtension implements WalletExtension {
    private final byte[] data = {1, 2, 3};

    private final boolean isMandatory;
    private final String id;

    public FooWalletExtension(String id, boolean isMandatory) {
        this.isMandatory = isMandatory;
        this.id = id;
    }

    @Override
    public String getWalletExtensionID() {
        return id;
    }

    @Override
    public boolean isWalletExtensionMandatory() {
        return isMandatory;
    }

    @Override
    public byte[] serializeWalletExtension() {
        return data;
    }

    @Override
    public void deserializeWalletExtension(Wallet wallet, byte[] data) {
        checkArgument(Arrays.equals(this.data, data));
    }
}
