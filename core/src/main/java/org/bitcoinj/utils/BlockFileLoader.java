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

package org.bitcoinj.utils;

import org.bitcoinj.base.Network;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.MessageSerializer;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.ProtocolException;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * <p>This class reads block files stored in the Bitcoin Core format. This is simply a way to concatenate
 * blocks together. Importing block data with this tool can be a lot faster than syncing over the network, if you
 * have the files available.</p>
 * 
 * <p>In order to comply with {@link Iterable}, {@link BlockFileIterator} swallows a lot of {@link IOException}s, which may result in a few
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
public class BlockFileLoader implements Iterable<Block> {
    private static final int BLOCKFILE_BUFFER_SIZE = 16 * 1024 * 1024;

    /**
     * Gets the list of files which contain blocks from Bitcoin Core.
     */
    public static List<File> getReferenceClientBlockFileList(File blocksDir) {
        checkArgument(blocksDir.isDirectory(), () ->
                "not a directory: " + blocksDir);
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
        File defaultBlocksDir = AppDataDirectory.getPath("Bitcoin").resolve("blocks").toFile();
        if (!defaultBlocksDir.isDirectory())
            throw new RuntimeException("Default blocks directory not found");
        return defaultBlocksDir;
    }

    private final List<File> files;
    private final long packetMagic;
    private final MessageSerializer serializer;

    public BlockFileLoader(Network network, File blocksDir) {
        this(network, getReferenceClientBlockFileList(blocksDir));
    }

    public BlockFileLoader(Network network, List<File> files) {
        this.files = files;
        NetworkParameters params = NetworkParameters.of(network);
        packetMagic = params.getPacketMagic();
        serializer = params.getDefaultSerializer();
    }

    @Deprecated
    public BlockFileLoader(NetworkParameters params, File blocksDir) {
        this(params.network(), getReferenceClientBlockFileList(blocksDir));
    }

    @Deprecated
    public BlockFileLoader(NetworkParameters params, List<File> files) {
        this.files = files;
        packetMagic = params.getPacketMagic();
        serializer = params.getDefaultSerializer();
    }


    /**
     * Iterates all the blocks in a single block file.
     */
    public class BlockFileIterator implements Iterator<ByteBuffer> {
        private final File file;
        private final BufferedInputStream currentFileStream;
        private ByteBuffer nextBlock = null;

        public BlockFileIterator(File blockFile) throws FileNotFoundException {
            this.file = blockFile;
            currentFileStream = new BufferedInputStream(new FileInputStream(blockFile), BLOCKFILE_BUFFER_SIZE);
        }

        @Override
        public boolean hasNext() {
            if (nextBlock == null)
                loadNextBlock();
            return nextBlock != null;
        }

        @Override
        public ByteBuffer next() throws NoSuchElementException {
            if (!hasNext())
                throw new NoSuchElementException();
            ByteBuffer next = nextBlock;
            nextBlock = null;
            return next;
        }

        private void loadNextBlock() {
            try {
                if (currentFileStream.available() < 1) {
                    nextBlock = null;
                    return;
                }
                int nextChar = currentFileStream.read();
                while (nextChar != -1) {
                    if (nextChar != ((packetMagic >>> 24) & 0xff)) {
                        nextChar = currentFileStream.read();
                        continue;
                    }
                    nextChar = currentFileStream.read();
                    if (nextChar != ((packetMagic >>> 16) & 0xff))
                        continue;
                    nextChar = currentFileStream.read();
                    if (nextChar != ((packetMagic >>> 8) & 0xff))
                        continue;
                    nextChar = currentFileStream.read();
                    if (nextChar == (packetMagic & 0xff))
                        break;
                }
                byte[] sizeBytes = new byte[4];
                int sizeBytesRead = currentFileStream.read(sizeBytes, 0, 4);
                if (sizeBytesRead != 4) {
                    nextBlock = null;
                    return;
                }
                long size = ByteUtils.readUint32(sizeBytes, 0);
                byte[] dataBytes = new byte[(int) size];
                int dataBytesRead = currentFileStream.read(dataBytes, 0, (int) size);
                if (dataBytesRead != size) {
                    nextBlock = null;
                    return;
                }
                try {
                    nextBlock = ByteBuffer.wrap(dataBytes);
                } catch (ProtocolException e) {
                    nextBlock = null;
                } catch (Exception e) {
                    throw new RuntimeException("unexpected problem with block in " + file, e);
                }
            } catch (IOException e) {
                nextBlock = null;
            }
        }

        @Override
        public void remove() throws UnsupportedOperationException {
            throw new UnsupportedOperationException();
        }
    }

    @Override
    public Iterator<Block> iterator() {
        return stream().iterator();
    }

    public Stream<Block> stream() {
        return streamBuffers()
                .map(serializer::makeBlock);
    }

    public Stream<ByteBuffer> streamBuffers() {
        return files.stream()
                .flatMap(this::fileBlockStream);
    }

    protected Stream<ByteBuffer> fileBlockStream(File file) {
        return StreamSupport.stream(fileBlockSpliterator(file), false);
    }

    protected Spliterator<ByteBuffer> fileBlockSpliterator(File file) {
        try {
            Iterator<ByteBuffer> iterator = new BlockFileIterator(file);
            int characteristics = Spliterator.DISTINCT | Spliterator.ORDERED;
            return Spliterators.spliteratorUnknownSize(iterator, characteristics);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
