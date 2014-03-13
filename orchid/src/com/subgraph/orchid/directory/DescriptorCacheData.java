package com.subgraph.orchid.directory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.subgraph.orchid.Descriptor;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.misc.GuardedBy;



public class DescriptorCacheData <T extends Descriptor> {

	/** 7 days */
	private final static long EXPIRY_PERIOD = 7 * 24 * 60 * 60 * 1000;
	
	@GuardedBy("this")
	private final Map<HexDigest, T> descriptorMap;
	
	@GuardedBy("this")
	private final List<T> allDescriptors;
	
	public DescriptorCacheData() {
		this.descriptorMap = new HashMap<HexDigest, T>();
		this.allDescriptors = new ArrayList<T>();
	}
	
	synchronized T findByDigest(HexDigest digest) {
		return descriptorMap.get(digest);
	}
	
	synchronized List<T> getAllDescriptors() {
		return new ArrayList<T>(allDescriptors);
	}

	synchronized boolean addDescriptor(T d) {
		if(descriptorMap.containsKey(d.getDescriptorDigest())) {
			return false;
		}
		descriptorMap.put(d.getDescriptorDigest(), d);
		allDescriptors.add(d);
		return true;
	}
	
	synchronized void clear() {
		descriptorMap.clear();
		allDescriptors.clear();
	}
	
	synchronized int cleanExpired() {
		final Set<T> expired = getExpiredSet();

		if(expired.isEmpty()) {
			return 0;
		}
		
		clear();
		int dropped = 0;
		for(T d: allDescriptors) {
			if(expired.contains(d)) {
				dropped += d.getBodyLength();
			} else {
				addDescriptor(d);
			}
		}
		
		return dropped;
	}

	private Set<T> getExpiredSet() {
		final long now = System.currentTimeMillis();
		final Set<T> expired = new HashSet<T>();
		for(T d: allDescriptors) {
			if(isExpired(d, now)) {
				expired.add(d);
			}
		}
		return expired;
	}

	private boolean isExpired(T d, long now) {
		return d.getLastListed() != 0 && d.getLastListed() < (now - EXPIRY_PERIOD);
	}
}
