package com.subgraph.orchid;

import java.security.NoSuchAlgorithmException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.net.SocketFactory;

import com.subgraph.orchid.circuits.TorInitializationTracker;
import com.subgraph.orchid.crypto.PRNGFixes;
import com.subgraph.orchid.dashboard.Dashboard;
import com.subgraph.orchid.directory.downloader.DirectoryDownloaderImpl;
import com.subgraph.orchid.sockets.OrchidSocketFactory;

/**
 * This class is the main entry-point for running a Tor proxy
 * or client.
 */
public class TorClient {
	private final static Logger logger = Logger.getLogger(TorClient.class.getName());
	private final TorConfig config;
	private final Directory directory;
	private final TorInitializationTracker initializationTracker;
	private final ConnectionCache connectionCache;
	private final CircuitManager circuitManager;
	private final SocksPortListener socksListener;
	private final DirectoryDownloaderImpl directoryDownloader;
	private final Dashboard dashboard;

	private boolean isStarted = false;
	private boolean isStopped = false;
	
	private final CountDownLatch readyLatch;
	
	public TorClient() {
		this(null);
	}

	public TorClient(DirectoryStore customDirectoryStore) {
		if(Tor.isAndroidRuntime()) {
			PRNGFixes.apply();
		}
		config = Tor.createConfig();
		directory = Tor.createDirectory(config, customDirectoryStore);
		initializationTracker = Tor.createInitalizationTracker();
		initializationTracker.addListener(createReadyFlagInitializationListener());
		connectionCache = Tor.createConnectionCache(config, initializationTracker);
		directoryDownloader = Tor.createDirectoryDownloader(config, initializationTracker);
		circuitManager = Tor.createCircuitManager(config, directoryDownloader, directory, connectionCache, initializationTracker);
		socksListener = Tor.createSocksPortListener(config, circuitManager);
		readyLatch = new CountDownLatch(1);
		dashboard = new Dashboard();
		dashboard.addRenderables(circuitManager, directoryDownloader, socksListener);
	}

	public TorConfig getConfig() {
		return config;
	}

	public SocketFactory getSocketFactory() {
		return new OrchidSocketFactory(this);
	}

	/**
	 * Start running the Tor client service.
	 */
	public synchronized void start() {
		if(isStarted) {
			return;
		}
		if(isStopped) {
			throw new IllegalStateException("Cannot restart a TorClient instance.  Create a new instance instead.");
		}
		logger.info("Starting Orchid (version: "+ Tor.getFullVersion() +")");
		verifyUnlimitedStrengthPolicyInstalled();
		directoryDownloader.start(directory);
		circuitManager.startBuildingCircuits();
		if(dashboard.isEnabledByProperty()) {
			dashboard.startListening();
		}
		isStarted = true;
	}
	
	public synchronized void stop() {
		if(!isStarted || isStopped) {
			return;
		}
		try {
			socksListener.stop();
			if(dashboard.isListening()) {
				dashboard.stopListening();
			}
			directoryDownloader.stop();
			circuitManager.stopBuildingCircuits(true);
			directory.close();
			connectionCache.close();
		} catch (Exception e) {
			logger.log(Level.WARNING, "Unexpected exception while shutting down TorClient instance: "+ e, e);
		} finally {
			isStopped = true;
		}
	}
	
	public Directory getDirectory() {
		return directory;
	}
	
	public ConnectionCache getConnectionCache() {
		return connectionCache;
	}

	public CircuitManager getCircuitManager() {
		return circuitManager;
	}

	public void waitUntilReady() throws InterruptedException {
		readyLatch.await();
	}

	public void waitUntilReady(long timeout) throws InterruptedException, TimeoutException {
		if(!readyLatch.await(timeout, TimeUnit.MILLISECONDS)) {
			throw new TimeoutException();
		}
	}
	
	public Stream openExitStreamTo(String hostname, int port) throws InterruptedException, TimeoutException, OpenFailedException {
		ensureStarted();
		return circuitManager.openExitStreamTo(hostname, port);
	}
	
	private synchronized void ensureStarted() {
		if(!isStarted) {
			throw new IllegalStateException("Must call start() first");
		}
	}

	public void enableSocksListener(int port) {
		socksListener.addListeningPort(port);
	}

	public void enableSocksListener() {
		enableSocksListener(9150);
	}
	
	public void enableDashboard() {
		if(!dashboard.isListening()) {
			dashboard.startListening();
		}
	}
	
	public void enableDashboard(int port) {
		dashboard.setListeningPort(port);
		enableDashboard();
	}
	
	public void disableDashboard() {
		if(dashboard.isListening()) {
			dashboard.stopListening();
		}
	}

	public void addInitializationListener(TorInitializationListener listener) {
		initializationTracker.addListener(listener);
	}

	public void removeInitializationListener(TorInitializationListener listener) {
		initializationTracker.removeListener(listener);
	}
	
	private TorInitializationListener createReadyFlagInitializationListener() {
		return new TorInitializationListener() {
			public void initializationProgress(String message, int percent) {}
			public void initializationCompleted() {
				readyLatch.countDown();
			}
		};
	}

	public static void main(String[] args) {
		final TorClient client = new TorClient();
		client.addInitializationListener(createInitalizationListner());
		client.start();
		client.enableSocksListener();
	}

	private static TorInitializationListener createInitalizationListner() {
		return new TorInitializationListener() {
			
			public void initializationProgress(String message, int percent) {
				System.out.println(">>> [ "+ percent + "% ]: "+ message);
			}
			
			public void initializationCompleted() {
				System.out.println("Tor is ready to go!");
			}
		};
	}
	
	private void verifyUnlimitedStrengthPolicyInstalled() {
		try {
			if(Cipher.getMaxAllowedKeyLength("AES") < 256) {
				final String message = "Unlimited Strength Jurisdiction Policy Files are required but not installed.";
				logger.severe(message);
				throw new TorException(message);
			}
		} catch (NoSuchAlgorithmException e) {
			logger.log(Level.SEVERE, "No AES provider found");
			throw new TorException(e);
		}  catch (NoSuchMethodError e) {
			logger.info("Skipped check for Unlimited Strength Jurisdiction Policy Files");
		}
	}
}
