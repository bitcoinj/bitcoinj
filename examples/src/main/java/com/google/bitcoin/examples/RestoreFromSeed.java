package com.google.bitcoin.examples;

import com.google.bitcoin.core.*;
import com.google.bitcoin.wallet.*;
import com.google.bitcoin.params.*;
import com.google.bitcoin.store.SPVBlockStore;
import com.google.bitcoin.kits.WalletAppKit;
import com.google.bitcoin.net.discovery.*;

import java.io.File;

// this example restores a wallet from a deterministic seed and re-syncs the blockchain again
public class RestoreFromSeed {

	public static void main(String[] args) throws Exception {
		// we reuse the code from the WalletAppKit example. have a look there for explanation
		NetworkParameters params = TestNet3Params.get();
		
		String seedCode = "yard impulse luxury drive today throw farm pepper survey wreck glass federal";
		String passphrase = "";
		Long creationtime = new Long(1409478661);
		
		DeterministicSeed seed = new DeterministicSeed(seedCode, passphrase, creationtime);
		
		Wallet wallet = Wallet.fromSeed(params, seed);
		
		// make sure to replay the blockchain. so that the wallet picks up the transaction (at least from the seed creation time)
		wallet.clearTransactions(0);
		
		// we need to delete the old chain file to sync the blockchain again to make sure the wallet picks up the transactions
		File chainFile = new File("restore-from-seed.spvchain");
		if(chainFile.exists()) { chainFile.delete(); }

		// in this example we manually setup the blockstore, blockchain and connect to the bitcoin peers  
		SPVBlockStore chainStore = new SPVBlockStore(params, chainFile); // where to store the block chain
        BlockChain chain = new BlockChain(params, chainStore); 
        PeerGroup peers = new PeerGroup(params, chain); 
        peers.addPeerDiscovery(new DnsDiscovery(params)); // how do we find peers
        
        chain.addWallet(wallet); // hook up the blockchain and our wallet - we need to know when new transactions arrive in a block
        peers.addWallet(wallet); // hook up the peers network and our wallet - we need to know when pending transactions arrive
        
        DownloadListener bListener = new DownloadListener(){
    		@Override
    	    public void doneDownload() {
    			System.out.println("blockchain downloaded");
    		}
    	};
    	// connect and sync the blockchain
    	peers.startAsync();
    	peers.awaitRunning();
        peers.startBlockChainDownload(bListener); // download the blockchain.... takes a looong time
        System.out.println("downloading");
        bListener.await();
        
        // done wallet is restored and it should have the correct balance
        System.out.println(wallet.toString());
        
        // shutting down again
        peers.stopAsync();
        peers.awaitTerminated();
        
        
        
        // !!!!!!!!
        // same code as above but using the WalletAppKit - much shorter
        //
        
        WalletAppKit kit = new WalletAppKit(params, new File("."), "restorefromseed-example");
        // the important part. give the kit a seed to restore from. This must happen before starting the kit (startAsync())
        kit.restoreWalletFromSeed(seed);
        
        kit.startAsync();
		kit.awaitRunning();
		System.out.println(kit.wallet().toString());
		
		System.out.println("send money to: "+ kit.wallet().currentReceiveAddress().toString());
		
		// shutting down again
		kit.stopAsync();
		kit.awaitTerminated();
	}

}
