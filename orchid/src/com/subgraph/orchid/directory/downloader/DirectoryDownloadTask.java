package com.subgraph.orchid.directory.downloader;

import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.DirectoryDownloader;
import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.Threading;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorConfig.AutoBoolValue;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.Timestamp;

public class DirectoryDownloadTask implements Runnable {
	private final static Logger logger = Logger.getLogger(DirectoryDownloadTask.class.getName());
	
	private final TorConfig config;
	private final Directory directory;
	
	private final DirectoryDownloader downloader;

	private final TorRandom random;
	private final DescriptorProcessor descriptorProcessor;

	private final ExecutorService executor = Threading.newPool("DirectoryDownloadTask worker");

	private volatile boolean isDownloadingCertificates;
	private volatile boolean isDownloadingConsensus;
	private final AtomicInteger outstandingDescriptorTasks;

	private ConsensusDocument currentConsensus;
	private Date consensusDownloadTime;

	private volatile boolean isStopped;
	
	DirectoryDownloadTask(TorConfig config, Directory directory, DirectoryDownloader downloader) {
		this.config = config;
		this.directory = directory;
		this.downloader = downloader;
		this.random = new TorRandom();
		this.outstandingDescriptorTasks = new AtomicInteger();
		this.descriptorProcessor = new DescriptorProcessor(config, directory);
	}
	
	public synchronized void stop() {
		if(isStopped) {
			return;
		}
		executor.shutdownNow();
		isStopped = true;
	}

	public void run() {
		directory.loadFromStore();
		directory.waitUntilLoaded();
		setCurrentConsensus(directory.getCurrentConsensusDocument());
		while (!isStopped) {
			checkCertificates();
			checkConsensus();
			checkDescriptors();
			try {
				Thread.sleep(5000);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				return;
			}
		}
	}

	private void checkCertificates() {
		if (isDownloadingCertificates
				|| directory.getRequiredCertificates().isEmpty()) {
			return;
		}

		isDownloadingCertificates = true;
		executor.execute(new DownloadCertificatesTask());
	}

	void setCurrentConsensus(ConsensusDocument consensus) {
		if (consensus != null) {
			currentConsensus = consensus;
			consensusDownloadTime = chooseDownloadTimeForConsensus(consensus);
		} else {
			currentConsensus = null;
			consensusDownloadTime = null;
		}
	}

	/*
	 * dir-spec 5.1: Downloading network-status documents
	 * 
	 *   To avoid swarming the caches whenever a consensus expires, the clients
	 *   download new consensuses at a randomly chosen time after the caches are
	 *   expected to have a fresh consensus, but before their consensus will
	 *   expire. (This time is chosen uniformly at random from the interval
	 *   between the time 3/4 into the first interval after the consensus is no
	 *   longer fresh, and 7/8 of the time remaining after that before the
	 *   consensus is invalid.)
	 * 
	 *   [For example, if a cache has a consensus that became valid at 1:00, and
	 *   is fresh until 2:00, and expires at 4:00, that cache will fetch a new
	 *   consensus at a random time between 2:45 and 3:50, since 3/4 of the
	 *   one-hour interval is 45 minutes, and 7/8 of the remaining 75 minutes is
	 *   65 minutes.]
	 */
	private Date chooseDownloadTimeForConsensus(ConsensusDocument consensus) {
		final long va = getMilliseconds(consensus.getValidAfterTime());
		final long fu = getMilliseconds(consensus.getFreshUntilTime());
		final long vu = getMilliseconds(consensus.getValidUntilTime());
		final long i1 = fu - va;
		final long start = fu + ((i1 * 3) / 4);
		final long i2 = ((vu - start) * 7) / 8;
		final long r = random.nextLong(i2);
		final long download = start + r;
		return new Date(download);
	}

	private boolean needConsensusDownload() {
		if(directory.hasPendingConsensus()) {
			return false;
		}
		if (currentConsensus == null || !currentConsensus.isLive()) {
			if(currentConsensus == null) {
				logger.info("Downloading consensus because we have no consensus document");
			} else {
				logger.info("Downloading consensus because the document we have is not live");
			}
			return true;
		}
		return consensusDownloadTime.before(new Date());
	}

	private long getMilliseconds(Timestamp ts) {
		return ts.getDate().getTime();
	}

	private void checkConsensus() {
		if (isDownloadingConsensus || !needConsensusDownload()) {
			return;
		}

		isDownloadingConsensus = true;
		executor.execute(new DownloadConsensusTask());
	}

	private void checkDescriptors() {
		if (outstandingDescriptorTasks.get() > 0) {
			return;
		}
		List<List<HexDigest>> ds = descriptorProcessor
				.getDescriptorDigestsToDownload();
		if (ds.isEmpty()) {
			return;
		}
		for (List<HexDigest> dlist : ds) {
			outstandingDescriptorTasks.incrementAndGet();
			executor.execute(new DownloadRouterDescriptorsTask(dlist, useMicrodescriptors()));
		}
	}
	
	private boolean useMicrodescriptors() {
		return config.getUseMicrodescriptors() != AutoBoolValue.FALSE;
	}
	
	private class DownloadConsensusTask implements Runnable {
		public void run() {
			try {
				final ConsensusDocument consensus = downloader.downloadCurrentConsensus(useMicrodescriptors());
				setCurrentConsensus(consensus);
				directory.addConsensusDocument(consensus, false);
				
			} catch (DirectoryRequestFailedException e) {
				logger.warning("Failed to download current consensus document: "+ e.getMessage());
			} finally {
				isDownloadingConsensus = false;
			}
		}
	}
	
	private class DownloadRouterDescriptorsTask implements Runnable {
		private final Set<HexDigest> fingerprints;
		private final boolean useMicrodescriptors;
		
		public DownloadRouterDescriptorsTask(Collection<HexDigest> fingerprints, boolean useMicrodescriptors) {
			this.fingerprints = new HashSet<HexDigest>(fingerprints);
			this.useMicrodescriptors = useMicrodescriptors;
		}
		
		public void run() {
			try {
				if(useMicrodescriptors) {
					directory.addRouterMicrodescriptors(downloader.downloadRouterMicrodescriptors(fingerprints));
				} else {
					directory.addRouterDescriptors(downloader.downloadRouterDescriptors(fingerprints));
				}
			} catch (DirectoryRequestFailedException e) {
				logger.warning("Failed to download router descriptors: "+ e.getMessage());
			} finally {
				outstandingDescriptorTasks.decrementAndGet();
			}
		}
	}

	private class DownloadCertificatesTask implements Runnable {
		public void run() {
			try {
				for(KeyCertificate c: downloader.downloadKeyCertificates(directory.getRequiredCertificates())) {
					directory.addCertificate(c);
				}
				directory.storeCertificates();
			} catch (DirectoryRequestFailedException e) {
				logger.warning("Failed to download key certificates: "+ e.getMessage());
			} finally {
				isDownloadingCertificates = false;
			}
		}
	}
}
