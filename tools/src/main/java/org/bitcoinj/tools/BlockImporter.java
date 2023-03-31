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

import org.bitcoinj.core.*;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.store.*;
import org.bitcoinj.utils.BlockFileLoader;

import java.io.File;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/** Very thin wrapper around {@link BlockFileLoader} */
public class BlockImporter {
    public static void main(String[] args) throws BlockStoreException, VerificationException, PrunedException {
        System.out.println("USAGE: BlockImporter (prod|test) (Disk|MemFull|Mem|SPV) [blockStore]");
        System.out.println("       blockStore is required unless type is Mem or MemFull");
        System.out.println("       Does full verification if the store supports it");
        checkArgument(args.length == 2 || args.length == 3);
        
        NetworkParameters params;
        if (args[0].equals("test"))
            params = TestNet3Params.get();
        else
            params = MainNetParams.get();

        BlockStore store;
        switch (args[1]) {
            case "MemFull":
                checkArgument(args.length == 2);
                store = new MemoryFullPrunedBlockStore(params, 100);
                break;
            case "Mem":
                checkArgument(args.length == 2);
                store = new MemoryBlockStore(params.getGenesisBlock());
                break;
            case "SPV":
                checkArgument(args.length == 3);
                store = new SPVBlockStore(params.getGenesisBlock(), new File(args[2]));
                break;
            default:
                System.err.println("Unknown store " + args[1]);
                return;
        }
        
        AbstractBlockChain chain = null;
        if (store instanceof FullPrunedBlockStore)
            chain = new FullPrunedBlockChain(params, (FullPrunedBlockStore) store);
        else
            chain = new BlockChain(params, store);
        
        BlockFileLoader loader = new BlockFileLoader(params.network(), BlockFileLoader.getReferenceClientBlockFileList());
        
        for (Block block : loader)
            chain.add(block);
    }
}
