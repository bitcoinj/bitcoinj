package com.subgraph.orchid;

import java.nio.ByteBuffer;
import java.util.List;

public interface DirectoryStore {
	enum CacheFile {
		CERTIFICATES("certificates"),
		CONSENSUS("consensus"),
		CONSENSUS_MICRODESC("consensus-microdesc"),
		MICRODESCRIPTOR_CACHE("cached-microdescs"),
		MICRODESCRIPTOR_JOURNAL("cached-microdescs.new"),
		DESCRIPTOR_CACHE("cached-descriptors"),
		DESCRIPTOR_JOURNAL("cached-descriptors.new"),
		STATE("state");

		final private String filename;

		CacheFile(String filename) {
			this.filename = filename;
		}

		public String getFilename() {
			return filename;
		}
	}

	ByteBuffer loadCacheFile(CacheFile cacheFile);
	void writeData(CacheFile cacheFile, ByteBuffer data);
	void writeDocument(CacheFile cacheFile, Document document);
	void writeDocumentList(CacheFile cacheFile, List<? extends Document> documents);
	void appendDocumentList(CacheFile cacheFile, List<? extends Document> documents);

	void removeCacheFile(CacheFile cacheFile);
	void removeAllCacheFiles();
}
