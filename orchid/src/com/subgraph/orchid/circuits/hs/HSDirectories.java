package com.subgraph.orchid.circuits.hs;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.data.HexDigest;

public class HSDirectories {
	private final static int DIR_CLUSTER_SZ = 3;
	private final Directory directory;
	private final TorRandom random;
	private ConsensusDocument currentConsensus;
	private List<Router> hsDirectories;
	
	HSDirectories(Directory directory) {
		this.directory = directory;
		this.hsDirectories = new ArrayList<Router>();
		this.random = new TorRandom();
	}
	
	List<HSDescriptorDirectory> getDirectoriesForHiddenService(HiddenService hs) {
		final List<HSDescriptorDirectory> dirs = new ArrayList<HSDescriptorDirectory>(2 * DIR_CLUSTER_SZ);
		for(HexDigest id: hs.getAllCurrentDescriptorIds()) {
			for(Router r: getDirectoriesForDescriptorId(id)) {
				dirs.add(new HSDescriptorDirectory(id, r));
			}
		}
		return dirs;
	}
	
	private List<Router> getDirectoriesForDescriptorId(HexDigest descriptorId) {
		final String hexId = descriptorId.toString();
		refreshFromDirectory();
		final int idx = getIndexForDescriptorId(hexId);
		return selectDirectoriesAtIndex(idx);
	}
	
	private int getIndexForDescriptorId(String hexId) {
		for(int i = 0; i < hsDirectories.size(); i++) {
			String routerId = getHexIdForIndex(i);
			if(routerId.compareTo(hexId) > 0) {
				return i;
			}
		}
		return 0;
	}
	
	private String getHexIdForIndex(int idx) {
		final Router r = hsDirectories.get(idx);
		return r.getIdentityHash().toString();
	}
	
	private List<Router> selectDirectoriesAtIndex(int idx) {
		if(idx < 0 || idx >= hsDirectories.size()) {
			throw new IllegalArgumentException("idx = "+ idx);
		}
		if(hsDirectories.size() < DIR_CLUSTER_SZ) {
			throw new IllegalStateException();
		}
		final List<Router> dirs = new ArrayList<Router>(DIR_CLUSTER_SZ);
		for(int i = 0; i < DIR_CLUSTER_SZ; i++) {
			dirs.add(hsDirectories.get(idx));
			idx += 1;
			if(idx == hsDirectories.size()) {
				idx = 0;
			}
		}
		randomShuffle(dirs);
		return dirs;
	}
	
	
	
	private void refreshFromDirectory() {
		ConsensusDocument consensus = directory.getCurrentConsensusDocument();
		if(currentConsensus == consensus) {
			return;
		}
		currentConsensus = consensus;
		hsDirectories.clear();
		for(Router r: directory.getAllRouters()) {
			if(r.isHSDirectory()) {
				hsDirectories.add(r);
			}
		}
		
		Collections.sort(hsDirectories, new Comparator<Router>() {
			public int compare(Router r1, Router r2) {
				final String s1 = r1.getIdentityHash().toString();
				final String s2 = r2.getIdentityHash().toString();
				return s1.compareTo(s2);
			}
		});
	}
	
	private void randomShuffle(List<Router> dirs) {
		for(int i = 0; i < dirs.size(); i++) {
			swap(dirs, i, random.nextInt(dirs.size()));
		}
	}
	
	private void swap(List<Router> dirs, int idx1, int idx2) {
		if(idx1 != idx2) {
			final Router r1 = dirs.get(idx1);
			final Router r2 = dirs.get(idx2);
			dirs.set(idx1, r2);
			dirs.set(idx2, r1);
		}
	}
}
