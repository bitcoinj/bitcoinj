package BackupToMnemonicSeed;

/**
 * The following example shows you how create a deterministic seed represented as a mnemonic from a wallet. 
 * This seed can be used to restore your wallet. The RestoreFromSeed.java example shows how to restore the wallet from this seed.
 * 
 * In Bitcoin Improvement Proposal (BIP) 39 and BIP 32 describe the details about hierarchical deterministic wallets and mnemonic sentence to represent their seeds 
 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */

import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Wallet;
import com.google.bitcoin.params.TestNet3Params;
import com.google.bitcoin.wallet.DeterministicSeed;
import com.google.common.base.Joiner;

public class BackupToMnemonicSeed {

    public static void main(String[] args) {

        NetworkParameters params = TestNet3Params.get();
        Wallet wallet = new Wallet(params);

        DeterministicSeed seed = wallet.getKeyChainSeed();
        System.out.println("seed: " + seed.toString());

        System.out.println("creation time: " + seed.getCreationTimeSeconds());
        System.out.println("mnemonicCode: " + Joiner.on(" ").join(seed.getMnemonicCode()));
    }
}
