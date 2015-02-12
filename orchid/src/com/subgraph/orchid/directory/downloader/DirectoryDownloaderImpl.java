package com.subgraph.orchid.directory.downloader;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import com.subgraph.orchid.CircuitManager;
import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.ConsensusDocument.RequiredCertificate;
import com.subgraph.orchid.Descriptor;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.DirectoryCircuit;
import com.subgraph.orchid.DirectoryDownloader;
import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.RouterDescriptor;
import com.subgraph.orchid.RouterMicrodescriptor;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.TorInitializationTracker;
import com.subgraph.orchid.data.HexDigest;

public class DirectoryDownloaderImpl implements DirectoryDownloader {
	private final static Logger logger = Logger.getLogger(DirectoryDownloaderImpl.class.getName());
	
	private final TorConfig config;
	private final TorInitializationTracker initializationTracker;
	private CircuitManager circuitManager;
	private boolean isStarted;
	private boolean isStopped;
	private DirectoryDownloadTask downloadTask;
	private Thread downloadTaskThread;
	

	public DirectoryDownloaderImpl(TorConfig config, TorInitializationTracker initializationTracker) {
		this.config = config;
		this.initializationTracker = initializationTracker;
	}

	public void setCircuitManager(CircuitManager circuitManager) {
		this.circuitManager = circuitManager;
	}

	public synchronized void start(Directory directory) {
		if(isStarted) {
			logger.warning("Directory downloader already running");
			return;
		}
		if(circuitManager == null) {
			throw new IllegalStateException("Must set CircuitManager instance with setCircuitManager() before starting.");
		}
	
		downloadTask = new DirectoryDownloadTask(config, directory, this);
		downloadTaskThread = new Thread(downloadTask);
		downloadTaskThread.start();
		isStarted = true;
	}
	
	public synchronized void stop() {
		if(!isStarted || isStopped) {
			return;
		}
		downloadTask.stop();
		downloadTaskThread.interrupt();
	}

	public RouterDescriptor downloadBridgeDescriptor(Router bridge) throws DirectoryRequestFailedException {
		final DirectoryDocumentRequestor requestor = new DirectoryDocumentRequestor(openBridgeCircuit(bridge));
		return requestor.downloadBridgeDescriptor(bridge);
	}

	
	public ConsensusDocument downloadCurrentConsensus(boolean useMicrodescriptors) throws DirectoryRequestFailedException  {
			return downloadCurrentConsensus(useMicrodescriptors, openCircuit());
	}

	public ConsensusDocument downloadCurrentConsensus(boolean useMicrodescriptors, DirectoryCircuit circuit) throws DirectoryRequestFailedException {
		final DirectoryDocumentRequestor requestor = new DirectoryDocumentRequestor(circuit, initializationTracker);
		return requestor.downloadCurrentConsensus(useMicrodescriptors);
	}

	public List<KeyCertificate> downloadKeyCertificates(Set<RequiredCertificate> required) throws DirectoryRequestFailedException {
		return downloadKeyCertificates(required, openCircuit());
	}

	public List<KeyCertificate> downloadKeyCertificates(Set<RequiredCertificate> required, DirectoryCircuit circuit) throws DirectoryRequestFailedException {
		final DirectoryDocumentRequestor requestor = new DirectoryDocumentRequestor(circuit, initializationTracker);
		return requestor.downloadKeyCertificates(required);
	}

	public List<RouterDescriptor> downloadRouterDescriptors(Set<HexDigest> fingerprints) throws DirectoryRequestFailedException {
		return downloadRouterDescriptors(fingerprints, openCircuit());
	}

	public List<RouterDescriptor> downloadRouterDescriptors(Set<HexDigest> fingerprints, DirectoryCircuit circuit) throws DirectoryRequestFailedException {
		final DirectoryDocumentRequestor requestor = new DirectoryDocumentRequestor(circuit, initializationTracker);
		final List<RouterDescriptor> ds =  requestor.downloadRouterDescriptors(fingerprints);
		return removeUnrequestedDescriptors(fingerprints, ds);
	}

	public List<RouterMicrodescriptor> downloadRouterMicrodescriptors(Set<HexDigest> fingerprints) throws DirectoryRequestFailedException {
		return downloadRouterMicrodescriptors(fingerprints, openCircuit());
	}

	public List<RouterMicrodescriptor> downloadRouterMicrodescriptors(Set<HexDigest> fingerprints, DirectoryCircuit circuit) throws DirectoryRequestFailedException {
		final DirectoryDocumentRequestor requestor = new DirectoryDocumentRequestor(circuit, initializationTracker);
		final List<RouterMicrodescriptor> ds =  requestor.downloadRouterMicrodescriptors(fingerprints);
		return removeUnrequestedDescriptors(fingerprints, ds);
	}
	
	private <T extends Descriptor> List<T> removeUnrequestedDescriptors(Set<HexDigest> requested, List<T> received) {
		final List<T> result = new ArrayList<T>();
		int unrequestedCount = 0;
		for(T d: received) {
			if(requested.contains(d.getDescriptorDigest())) {
				result.add(d);
			} else {
				unrequestedCount += 1;
			}
		}
		if(unrequestedCount > 0) {
			logger.warning("Discarding "+ unrequestedCount + " received descriptor(s) with fingerprints that did not match requested descriptors");
		}
		return result;
	}
	
	private DirectoryCircuit openCircuit() throws DirectoryRequestFailedException {
		try {
			return circuitManager.openDirectoryCircuit();
		} catch (OpenFailedException e) {
			throw new DirectoryRequestFailedException("Failed to open directory circuit", e);
		}
	}
	
	private DirectoryCircuit openBridgeCircuit(Router bridge) throws DirectoryRequestFailedException {
		try {
			return circuitManager.openDirectoryCircuitTo(Arrays.asList(bridge));
		} catch (OpenFailedException e) {
			throw new DirectoryRequestFailedException("Failed to open directory circuit to bridge "+ bridge, e);
		}
	}
}
