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

import static com.google.common.base.Preconditions.checkArgument;

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
import java.util.Locale;
import java.util.NoSuchElementException;

/**
 * <p>This class reads block files stored in the Bitcoin Core format. This is simply a way to concatenate
 * blocks together. Importing block data with this tool can be a lot faster than syncing over the network, if you
 * have the files available.</p>
 * 
 * <p>In order to comply with {@link Iterator}, this class swallows a lot of {@link IOException}s, which may result in a few
 * blocks being missed followed by a huge set of orphan blocks.</p>
 * 
 * <p>To blindly import all files which can be found in Bitcoin Core (version 0.8 or higher) datadir automatically,
 * try this code fragment:
 * {@code
 * BlockFileLoader loader = new BlockFileLoader(BlockFileLoader.getReferenceClientBlockFileList());
 * for (Block block : loader) {
 * try { chain.add(block); } catch (Exception e) { }
 * }
 * }</p>
 */
public class BlockFileLoader implements Iterable<Block>, Iterator<Block> {
    /**
     * Gets the list of files which contain blocks from Bitcoin Core.
     */
    public static List<File> getReferenceClientBlockFileList(File blocksDir) {
        checkArgument(blocksDir.isDirectory(), "%s is not a directory", blocksDir);
        List<File> list = new LinkedList<>();
        for (int i = 0; true; i++) {
            File file = new File(blocksDir, String.format(Locale.US, "blk%05d.dat", i));
            if (!file.exists())
                break;
            list.add(file);
        }
        return list;
    }

    public static List<File> getReferenceClientBlockFileList() {
        return getReferenceClientBlockFileList(defaultBlocksDir());
    }

    public static File defaultBlocksDir() {
        final File defaultBlocksDir;
        if (Utils.isWindows()) {
            defaultBlocksDir = new File(System.getenv("APPDATA") + "\\.bitcoin\\blocks\\");
        } else if (Utils.isMac()) {
            defaultBlocksDir = new File(System.getProperty("user.home") + "/Library/Application Support/Bitcoin/blocks/");
        } else if (Utils.isLinux()) {
            defaultBlocksDir = new File(System.getProperty("user.home") + "/.bitcoin/blocks/");
        } else {
            throw new RuntimeException("Unsupported system");
        }
        return defaultBlocksDir;
    }

    private Iterator<File> fileIt;
    private File file = null;
    private FileInputStream currentFileStream = null;
    private Block nextBlock = null;
    private NetworkParameters params;

    public BlockFileLoader(NetworkParameters params, File blocksDir) {
        this(params, getReferenceClientBlockFileList(blocksDir));
    }

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
                file = fileIt.next();
                try {
                    currentFileStream = new FileInputStream(file);
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
                    nextBlock = params.getDefaultSerializer().makeBlock(bytes);
                } catch (ProtocolException e) {
                    nextBlock = null;
                    continue;
                } catch (Exception e) {
                    throw new RuntimeException("unexpected problem with block in " + file, e);
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
