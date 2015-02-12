package com.subgraph.orchid.directory.downloader;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorConfig.AutoBoolValue;
import com.subgraph.orchid.data.HexDigest;

public class DescriptorProcessor {
	private final static int MAX_DL_PER_REQUEST = 96;
	private final static int MAX_DL_TO_DELAY = 16;
	private final static int MIN_DL_REQUESTS = 3;
	private final static int MAX_CLIENT_INTERVAL_WITHOUT_REQUEST = 10 * 60 * 1000;

	private final TorConfig config;
	private final Directory directory;
	
	private Date lastDescriptorDownload;
	
	
	DescriptorProcessor(TorConfig config, Directory directory) {
		this.config = config;
		this.directory = directory;
	}

	private boolean canDownloadDescriptors(int downloadableCount) {
		if(downloadableCount >= MAX_DL_TO_DELAY)
			return true;
		if(downloadableCount == 0)
			return false;
		if(lastDescriptorDownload == null)
			return true;
		final Date now = new Date();
		final long diff = now.getTime() - lastDescriptorDownload.getTime();
		return diff > MAX_CLIENT_INTERVAL_WITHOUT_REQUEST;
	}

	/*
	 * dir-spec.txt section 5.3
	 */
	private List< List<HexDigest> > partitionDescriptors(List<Router> descriptors) {
		final int size = descriptors.size();
		final List< List<HexDigest> > partitions = new ArrayList< List<HexDigest> >();
		if(size <= 10) {
			partitions.add(createPartitionList(descriptors, 0, size));
			return partitions;
		} else if(size <= (MIN_DL_REQUESTS * MAX_DL_PER_REQUEST)) {
			final int chunk = size / MIN_DL_REQUESTS;
			int over = size % MIN_DL_REQUESTS;
			int off = 0;
			for(int i = 0; i < MIN_DL_REQUESTS; i++) {
				int sz = chunk;
				if(over != 0) {
					sz++;
					over--;
				}
				partitions.add(createPartitionList(descriptors, off, sz));
				off += sz;
			}
			return partitions;
			
		} else {
			int off = 0;
			while(off < descriptors.size()) {
				partitions.add(createPartitionList(descriptors, off, MAX_DL_PER_REQUEST));
				off += MAX_DL_PER_REQUEST;
			}
			return partitions;	
		}
	}

	private List<HexDigest> createPartitionList(List<Router> descriptors, int offset, int size) {
		final List<HexDigest> newList = new ArrayList<HexDigest>();
		for(int i = offset; i < (offset + size) && i < descriptors.size(); i++) {
			final HexDigest digest = getDescriptorDigestForRouter(descriptors.get(i));
			newList.add(digest);
		}
		return newList;
	}

	private HexDigest getDescriptorDigestForRouter(Router r) {
		if(useMicrodescriptors()) {
			return r.getMicrodescriptorDigest();
		} else {
			return r.getDescriptorDigest();
		}
	}
	
	private boolean useMicrodescriptors() {
		return config.getUseMicrodescriptors() != AutoBoolValue.FALSE;
	}

	List< List<HexDigest> > getDescriptorDigestsToDownload() {
		final ConsensusDocument consensus = directory.getCurrentConsensusDocument();
		if(consensus == null || !consensus.isLive()) {
			return Collections.emptyList();
		}
		final List<Router> downloadables = directory.getRoutersWithDownloadableDescriptors();
		if(!canDownloadDescriptors(downloadables.size())) {
			return Collections.emptyList();
		}
		
		lastDescriptorDownload = new Date();
		return partitionDescriptors(downloadables);
	}
}
