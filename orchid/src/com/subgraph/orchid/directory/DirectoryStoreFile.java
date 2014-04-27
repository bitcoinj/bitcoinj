package com.subgraph.orchid.directory;

import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.WritableByteChannel;
import java.util.List;
import java.util.logging.Logger;

import com.subgraph.orchid.Document;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.crypto.TorRandom;

public class DirectoryStoreFile {
	private final static Logger logger = Logger.getLogger(DirectoryStoreFile.class.getName());
	private final static ByteBuffer EMPTY_BUFFER = ByteBuffer.allocate(0);
	private final static TorRandom random = new TorRandom();
	
	private final TorConfig config;
	private final String cacheFilename;
	
	private RandomAccessFile openFile;
	
	private boolean openFileFailed;
	private boolean directoryCreationFailed;
	
	DirectoryStoreFile(TorConfig config, String cacheFilename) {
		this.config = config;
		this.cacheFilename = cacheFilename;
	}
	
	public void writeData(ByteBuffer data) {
		final File tempFile = createTempFile();
		final FileOutputStream fos = openFileOutputStream(tempFile);
		if(fos == null) {
			return;
		}
		try {
			writeAllToChannel(fos.getChannel(), data);
			quietClose(fos);
			installTempFile(tempFile);
		} catch (IOException e) {
			logger.warning("I/O error writing to temporary cache file "+ tempFile + " : "+ e);
			return;
		} finally {
			quietClose(fos);
			tempFile.delete();
		}
	}

	public void writeDocuments(List<? extends Document> documents) {
		final File tempFile = createTempFile();
		final FileOutputStream fos = openFileOutputStream(tempFile);
		if(fos == null) {
			return;
		}
		try {
			writeDocumentsToChannel(fos.getChannel(), documents);
			quietClose(fos);
			installTempFile(tempFile);
		} catch (IOException e) {
			logger.warning("I/O error writing to temporary cache file "+ tempFile + " : "+ e);
			return;
		} finally {
			quietClose(fos);
			tempFile.delete();
		}
	}
	
	private FileOutputStream openFileOutputStream(File file) {
		try {
			createDirectoryIfMissing();
			return new FileOutputStream(file);
		} catch (FileNotFoundException e) {
			logger.warning("Failed to open file "+ file + " : "+ e);
			return null;
		}
	}

	public void appendDocuments(List<? extends Document> documents) {
		if(!ensureOpened()) {
			return;
		}
		try {
			final FileChannel channel = openFile.getChannel();
			channel.position(channel.size());
			writeDocumentsToChannel(channel, documents);
			channel.force(true);
		} catch (IOException e) {
			logger.warning("I/O error writing to cache file "+ cacheFilename);
			return;
		}
	}
	
	public ByteBuffer loadContents() {
		if(!(fileExists() && ensureOpened())) {
			return EMPTY_BUFFER;
		}
		
		try {
			return readAllFromChannel(openFile.getChannel());
		} catch (IOException e) {
			logger.warning("I/O error reading cache file "+ cacheFilename + " : "+ e);
			return EMPTY_BUFFER;
		}
	}
	
	private ByteBuffer readAllFromChannel(FileChannel channel) throws IOException {
		channel.position(0);
		final ByteBuffer buffer = createBufferForChannel(channel);
		while(buffer.hasRemaining()) {
			if(channel.read(buffer) == -1) {
				logger.warning("Unexpected EOF reading from cache file");
				return EMPTY_BUFFER;
			}
		}
		buffer.rewind();
		return buffer;
	}

	private ByteBuffer createBufferForChannel(FileChannel channel) throws IOException {
		final int sz = (int) (channel.size() & 0xFFFFFFFF);
		return ByteBuffer.allocateDirect(sz);
	}
	
	void close() {
		if(openFile != null) {
			quietClose(openFile);
			openFile = null;
		}
	}
	
	private boolean fileExists() {
		final File file = getFile();
		return file.exists();
	}

	private boolean ensureOpened() {
		if(openFileFailed) {
			return false;
		}
		if(openFile != null) {
			return true;
		}
		openFile = openFile();
		return openFile != null;
	}

	private RandomAccessFile openFile() {
		try {
			final File f = new File(config.getDataDirectory(), cacheFilename);
			createDirectoryIfMissing();
			return new RandomAccessFile(f, "rw");
		} catch (FileNotFoundException e) {
			openFileFailed = true;
			logger.warning("Failed to open cache file "+ cacheFilename);
			return null;
		}
	}
	
	private void installTempFile(File tempFile) {
		close();
		final File target = getFile();
		if(target.exists() && !target.delete()) {
			logger.warning("Failed to delete file "+ target);
		}
		if(!tempFile.renameTo(target)) {
			logger.warning("Failed to rename temp file "+ tempFile +" to "+ target);
		}
		tempFile.delete();
		ensureOpened();
	}

	private File createTempFile() {
		final long n = random.nextLong();
		final File f = new File(config.getDataDirectory(), cacheFilename + Long.toString(n));
		f.deleteOnExit();
		return f;
	}
	
	private void writeDocumentsToChannel(FileChannel channel, List<? extends Document> documents) throws IOException {
		for(Document d: documents) {
			writeAllToChannel(channel, d.getRawDocumentBytes());
		}
	}

	private void writeAllToChannel(WritableByteChannel channel, ByteBuffer data) throws IOException {
		data.rewind();
		while(data.hasRemaining()) {
			channel.write(data);
		}
	}
	
	private void quietClose(Closeable closeable) {
		try {
			closeable.close();
		} catch (IOException e) {}
	}
	
	private File getFile() {
		return new File(config.getDataDirectory(), cacheFilename);
	}

	public void remove() {
		close();
		getFile().delete();
	}
	
	private void createDirectoryIfMissing() {
		if(directoryCreationFailed) {
			return;
		}
		final File dd = config.getDataDirectory();
		if(!dd.exists()) {
			if(!dd.mkdirs()) {
				directoryCreationFailed = true;
				logger.warning("Failed to create data directory "+ dd);
			}
		}
	}
}
