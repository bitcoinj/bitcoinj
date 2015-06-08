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

package org.bitcoinj.utils;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.ProtocolException;
import org.bitcoinj.core.Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * <p>This class reads block files stored in the reference/Satoshi client format. This is simply a way to concatenate
 * blocks together. Importing block data with this tool can be a lot faster than syncing over the network, if you
 * have the files available.</p>
 * 
 * <p>In order to comply with Iterator&lt;Block>, this class swallows a lot of IOExceptions, which may result in a few
 * blocks being missed followed by a huge set of orphan blocks.</p>
 * 
 * <p>To blindly import all files which can be found in a reference client (version >= 0.8) datadir automatically,
 * try this code fragment:<br>
 * BlockFileLoader loader = new BlockFileLoader(BlockFileLoader.getReferenceClientBlockFileList());<br>
 * for (Block block : loader) {<br>
 * &nbsp;&nbsp;try { chain.add(block); } catch (Exception e) { }<br>
 * }</p>
 */
public class BlockFileLoader implements Iterable<Block>, Iterator<Block> {
    /**
     * Gets the list of files which contain blocks from the Satoshi client.
     */
    public static List<File> getReferenceClientBlockFileList() {
        String defaultDataDir;
        String OS = System.getProperty("os.name").toLowerCase();
        if (OS.indexOf("win") >= 0) {
            defaultDataDir = System.getenv("APPDATA") + "\\.bitcoin\\blocks\\";
        } else if (OS.indexOf("mac") >= 0 || (OS.indexOf("darwin") >= 0)) {
            defaultDataDir = System.getProperty("user.home") + "/Library/Application Support/Bitcoin/blocks/";
        } else {
            defaultDataDir = System.getProperty("user.home") + "/.bitcoin/blocks/";
        }
        
        List<File> list = new LinkedList<File>();
        for (int i = 0; true; i++) {
            File file = new File(defaultDataDir + String.format("blk%05d.dat", i));
            if (!file.exists())
                break;
            list.add(file);
        }
        return list;
    }
    
    private Iterator<File> fileIt;
    private FileInputStream currentFileStream = null;
    private Block nextBlock = null;
    private NetworkParameters params;
    
    public BlockFileLoader(NetworkParameters params, List<File> files) {
        fileIt = files.iterator();
        this.params = params;
    }
    
    @Override
    public boolean hasNext() {
        if (nextBlock == null)
            loadNextBlock();
        return nextBlock != null;
    }

    @Override
    public Block next() throws NoSuchElementException {
        if (!hasNext())
            throw new NoSuchElementException();
        Block next = nextBlock;
        nextBlock = null;
        return next;
    }
    
    private void loadNextBlock() {
        while (true) {
            try {
                if (!fileIt.hasNext() && (currentFileStream == null || currentFileStream.available() < 1))
                    break;
            } catch (IOException e) {
                currentFileStream = null;
                if (!fileIt.hasNext())
                    break;
            }
            while (true) {
                try {
                    if (currentFileStream != null && currentFileStream.available() > 0)
                        break;
                } catch (IOException e1) {
                    currentFileStream = null;
                }
                if (!fileIt.hasNext()) {
                    nextBlock = null;
                    currentFileStream = null;
                    return;
                }
                try {
                    currentFileStream = new FileInputStream(fileIt.next());
                } catch (FileNotFoundException e) {
                    currentFileStream = null;
                }
            }
            try {
                int nextChar = currentFileStream.read();
                while (nextChar != -1) {
                    if (nextChar != ((params.getPacketMagic() >>> 24) & 0xff)) {
                        nextChar = currentFileStream.read();
                        continue;
                    }
                    nextChar = currentFileStream.read();
                    if (nextChar != ((params.getPacketMagic() >>> 16) & 0xff))
                        continue;
                    nextChar = currentFileStream.read();
                    if (nextChar != ((params.getPacketMagic() >>> 8) & 0xff))
                        continue;
                    nextChar = currentFileStream.read();
                    if (nextChar == (params.getPacketMagic() & 0xff))
                        break;
                }
                byte[] bytes = new byte[4];
                currentFileStream.read(bytes, 0, 4);
                long size = Utils.readUint32BE(Utils.reverseBytes(bytes), 0);
                // We allow larger than MAX_BLOCK_SIZE because test code uses this as well.
                if (size > Block.MAX_BLOCK_SIZE*2 || size <= 0)
                    continue;
                bytes = new byte[(int) size];
                currentFileStream.read(bytes, 0, (int) size);
                try {
                    nextBlock = new Block(params, bytes);
                } catch (ProtocolException e) {
                    nextBlock = null;
                    continue;
                }
                break;
            } catch (IOException e) {
                currentFileStream = null;
                continue;
            }
        }
    }

    @Override
    public void remove() throws UnsupportedOperationException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Iterator<Block> iterator() {
        return this;
    }
}
