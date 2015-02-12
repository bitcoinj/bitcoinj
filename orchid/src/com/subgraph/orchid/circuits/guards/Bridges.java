package com.subgraph.orchid.circuits.guards;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import com.subgraph.orchid.BridgeRouter;
import com.subgraph.orchid.DirectoryDownloader;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.RouterDescriptor;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.config.TorConfigBridgeLine;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.directory.downloader.DirectoryRequestFailedException;

public class Bridges {
	private static final Logger logger = Logger.getLogger(Bridges.class.getName());
	
	private class DescriptorDownloader implements Runnable {

		private final BridgeRouterImpl target;
		
		DescriptorDownloader(BridgeRouterImpl target) {
			this.target = target;
		}
	
		public void run() {
			try {
				downloadDescriptor();
			} finally {
				decrementOutstandingTasks();
			}
		}
		
		private void downloadDescriptor() {
			logger.fine("Downloading descriptor for bridge: "+ target);
			try {
				final RouterDescriptor descriptor = directoryDownloader.downloadBridgeDescriptor(target);
				if(descriptor != null) {
					logger.fine("Descriptor received for bridge "+ target +". Adding to list of usable bridges");
					target.setDescriptor(descriptor);
					synchronized(lock) {
						bridgeRouters.add(target);
						lock.notifyAll();
					}
				}
			} catch (DirectoryRequestFailedException e) {
				logger.warning("Failed to download descriptor for bridge: "+ e.getMessage());
			}
		}
		
		private void decrementOutstandingTasks() {
			if(outstandingDownloadTasks.decrementAndGet() == 0) {
				logger.fine("Initial descriptor fetch complete");
				synchronized(lock) {
					bridgesInitialized = true;
					lock.notifyAll();
				}
			}
		}
	}

	private final TorConfig config;
	private final DirectoryDownloader directoryDownloader;
	
	private final Set<BridgeRouterImpl> bridgeRouters;
	private final TorRandom random;
	private final Object lock;
	
	/** Initialization started */
	private boolean bridgesInitializing;
	/** Initialization completed */
	private boolean bridgesInitialized;

	private AtomicInteger outstandingDownloadTasks;
	
	Bridges(TorConfig config, DirectoryDownloader directoryDownloader) {
		this.config = config;
		this.directoryDownloader = directoryDownloader;
		this.bridgeRouters = new HashSet<BridgeRouterImpl>();
		this.random = new TorRandom();
		this.lock = new Object();
		this.outstandingDownloadTasks = new AtomicInteger();
	}

	BridgeRouter chooseRandomBridge(Set<Router> excluded) throws InterruptedException {
		
		synchronized(lock) {
			if(!bridgesInitialized && !bridgesInitializing) {
				initializeBridges();
			}
			while(!bridgesInitialized && !hasCandidates(excluded)) {
				lock.wait();
			}
			final List<BridgeRouter> candidates = getCandidates(excluded);
			if(candidates.isEmpty()) {
				logger.warning("Bridges enabled but no usable bridges configured");
				return null;
			}
			return candidates.get(random.nextInt(candidates.size()));
		}
	}

	private boolean hasCandidates(Set<Router> excluded) {
		return !(getCandidates(excluded).isEmpty());
	}
	
	private List<BridgeRouter> getCandidates(Set<Router> excluded) {
		if(bridgeRouters.isEmpty()) {
			return Collections.emptyList();
		}
		final List<BridgeRouter> candidates = new ArrayList<BridgeRouter>(bridgeRouters.size());
		for(BridgeRouter br: bridgeRouters) {
			if(!excluded.contains(br)) {
				candidates.add(br);
			}
		}
		return candidates;
	}

	private void initializeBridges() {
		logger.fine("Initializing bridges...");
		synchronized(lock) {
			if(bridgesInitializing || bridgesInitialized) {
				return;
			}
			if(directoryDownloader == null) {
				throw new IllegalStateException("Cannot download bridge descriptors because DirectoryDownload instance not initialized");
			}
			bridgesInitializing = true;
			startAllDownloadTasks();
		}
	}
	
	private List<Runnable> createDownloadTasks() {
		final List<Runnable> tasks = new ArrayList<Runnable>();
		for(TorConfigBridgeLine line: config.getBridges()) {
			tasks.add(new DescriptorDownloader(createBridgeFromLine(line)));
		}
		return tasks;
	}
	
	private void startAllDownloadTasks() {
		final List<Runnable> tasks = createDownloadTasks();
		outstandingDownloadTasks.set(tasks.size());
		for(Runnable r: tasks) {
			final Thread thread = new Thread(r);
			thread.start();
		}
	}
	
	private BridgeRouterImpl createBridgeFromLine(TorConfigBridgeLine line) {
		final BridgeRouterImpl bridge = new BridgeRouterImpl(line.getAddress(), line.getPort());
		if(line.getFingerprint() != null) {
			bridge.setIdentity(line.getFingerprint());
		}
		return bridge;
	}
}
