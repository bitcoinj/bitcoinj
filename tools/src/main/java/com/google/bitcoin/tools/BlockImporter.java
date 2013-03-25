/*
 * Copyright 2012 Matt Corallo.
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

package com.google.bitcoin.tools;

import com.google.bitcoin.core.Block;
import com.google.bitcoin.core.FullPrunedBlockChain;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Utils;
import com.google.bitcoin.store.FullPrunedBlockStore;
import com.google.bitcoin.store.H2FullPrunedBlockStore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * This class reads block files stored in the reference/Satoshi clients format. This is simply a way to concatenate
 * blocks together. Importing block data with this tool can be a lot faster than syncing over the network, if you
 * have the files available.
 */
public class BlockImporter {
    public static void main(String[] args) throws Exception {
        NetworkParameters params = NetworkParameters.prodNet();
        FullPrunedBlockStore store = new H2FullPrunedBlockStore(params, "toy-full.blockchain", 100);
        FullPrunedBlockChain chain = new FullPrunedBlockChain(params, store);
        
        String defaultDataDir;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            defaultDataDir = System.getenv("APPDATA") + "\\.bitcoin\\blocks\\";
        } else {
            defaultDataDir = System.getProperty("user.home") + "/.bitcoin/blocks/";
        }
        
        // TODO: Move this to a library function
        int i = 0;
        for (int j = 0; true; j++) {
            FileInputStream stream;
            System.out.println("Opening " + defaultDataDir + String.format("blk%05d.dat", j));
            try {
                stream = new FileInputStream(new File(
                        defaultDataDir + String.format("blk%05d.dat", j)));
            } catch (FileNotFoundException e1) {
                System.out.println(defaultDataDir + String.format("blk%05d.dat", j));
                break;
            }
            while (stream.available() > 0) {
                try {
                    int nextChar = stream.read();
                    while (nextChar != -1) {
                        if (nextChar != ((params.packetMagic >>> 24) & 0xff)) {
                            nextChar = stream.read();
                            continue;
                        }
                        nextChar = stream.read();
                        if (nextChar != ((params.packetMagic >>> 16) & 0xff))
                            continue;
                        nextChar = stream.read();
                        if (nextChar != ((params.packetMagic >>> 8) & 0xff))
                            continue;
                        nextChar = stream.read();
                        if (nextChar == (params.packetMagic & 0xff))
                            break;
                    }
                } catch (IOException e) {
                    break;
                }
                byte[] bytes = new byte[4];
                stream.read(bytes, 0, 4);
                long size = Utils.readUint32BE(Utils.reverseBytes(bytes), 0);
                if (size > Block.MAX_BLOCK_SIZE || size <= 0)
                    continue;
                bytes = new byte[(int) size];
                stream.read(bytes, 0, (int) size);
                Block block = new Block(params, bytes);
                if (store.get(block.getHash()) == null)
                    chain.add(block);

                if (i % 1000 == 0)
                    System.out.println(i);
                i++;
            }
            stream.close();
        }
        System.out.println("Imported " + chain.getChainHead().getHeight() + " blocks.");
        System.exit(0);
    }
}
