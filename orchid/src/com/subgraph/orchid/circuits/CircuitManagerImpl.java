package com.subgraph.orchid.circuits;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;

import com.subgraph.orchid.Circuit;
import com.subgraph.orchid.CircuitBuildHandler;
import com.subgraph.orchid.CircuitManager;
import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.Connection;
import com.subgraph.orchid.ConnectionCache;
import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.DirectoryCircuit;
import com.subgraph.orchid.ExitCircuit;
import com.subgraph.orchid.InternalCircuit;
import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.StreamConnectFailedException;
import com.subgraph.orchid.Threading;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.guards.EntryGuards;
import com.subgraph.orchid.circuits.hs.HiddenServiceManager;
import com.subgraph.orchid.circuits.path.CircuitPathChooser;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.dashboard.DashboardRenderable;
import com.subgraph.orchid.dashboard.DashboardRenderer;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.directory.downloader.DirectoryDownloaderImpl;

public class CircuitManagerImpl implements CircuitManager, DashboardRenderable {
	private final static int OPEN_DIRECTORY_STREAM_RETRY_COUNT = 5;
	private final static int OPEN_DIRECTORY_STREAM_TIMEOUT = 10 * 1000;
	
	interface CircuitFilter {
		boolean filter(Circuit circuit);
	}

	private final TorConfig config;
	private final Directory directory;
	private final ConnectionCache connectionCache;
	private final Set<CircuitImpl> activeCircuits;
	private final Queue<InternalCircuit> cleanInternalCircuits;
	private int requestedInternalCircuitCount = 0;
	private int pendingInternalCircuitCount = 0;
	private final TorRandom random;
	private final PendingExitStreams pendingExitStreams;
	private final ScheduledExecutorService scheduledExecutor = Threading.newSingleThreadScheduledPool("CircuitManager worker");
	private final CircuitCreationTask circuitCreationTask;
	private final TorInitializationTracker initializationTracker;
	private final CircuitPathChooser pathChooser;
	private final HiddenServiceManager hiddenServiceManager;
	private final ReentrantLock lock = Threading.lock("circuitManager");

	private boolean isBuilding = false;

	public CircuitManagerImpl(TorConfig config, DirectoryDownloaderImpl directoryDownloader, Directory directory, ConnectionCache connectionCache, TorInitializationTracker initializationTracker) {
		this.config = config;
		this.directory = directory;
		this.connectionCache = connectionCache;
		this.pathChooser = CircuitPathChooser.create(config, directory);
		if(config.getUseEntryGuards() || config.getUseBridges()) {
			this.pathChooser.enableEntryGuards(new EntryGuards(config, connectionCache, directoryDownloader, directory));
		}
		this.pendingExitStreams = new PendingExitStreams(config);
		this.circuitCreationTask = new CircuitCreationTask(config, directory, connectionCache, pathChooser, this, initializationTracker);
		this.activeCircuits = new HashSet<CircuitImpl>();
		this.cleanInternalCircuits = new LinkedList<InternalCircuit>();
		this.random = new TorRandom();
		
		this.initializationTracker = initializationTracker;
		this.hiddenServiceManager = new HiddenServiceManager(config, directory, this);
		
		directoryDownloader.setCircuitManager(this);
	}

	public void startBuildingCircuits() {
		lock.lock();
		try {
			isBuilding = true;
			scheduledExecutor.scheduleAtFixedRate(circuitCreationTask, 0, 1000, TimeUnit.MILLISECONDS);
		} finally {
			lock.unlock();
		}
	}

	public void stopBuildingCircuits(boolean killCircuits) {
		lock.lock();
		try {
			isBuilding = false;
			scheduledExecutor.shutdownNow();
		} finally {
			lock.unlock();
		}

		if (killCircuits) {
			ArrayList<CircuitImpl> circuits;
			synchronized (activeCircuits) {
				circuits = new ArrayList<CircuitImpl>(activeCircuits);
			}
			for (CircuitImpl c : circuits) {
				c.destroyCircuit();
			}
		}
	}

	public ExitCircuit createNewExitCircuit(Router exitRouter) {
		return CircuitImpl.createExitCircuit(this, exitRouter);
	}

	void addActiveCircuit(CircuitImpl circuit) {
		synchronized (activeCircuits) {
			activeCircuits.add(circuit);
			activeCircuits.notifyAll();
		}

		boolean doDestroy;
		lock.lock();
		try {
			doDestroy = !isBuilding;
		} finally {
			lock.unlock();
		}

		if (doDestroy) {
			// we were asked to stop since this circuit was started
			circuit.destroyCircuit();
		}
	}
	
	void removeActiveCircuit(CircuitImpl circuit) {
		synchronized (activeCircuits) {
			activeCircuits.remove(circuit);
		}
	}

	int getActiveCircuitCount() {
		synchronized (activeCircuits) {
			return activeCircuits.size();
		}
	}

	Set<Circuit> getPendingCircuits() {
		return getCircuitsByFilter(new CircuitFilter() {
			public boolean filter(Circuit circuit) {
				return circuit.isPending();
			}
		});
	}

	int getPendingCircuitCount() {
		lock.lock();
		try {
			return getPendingCircuits().size();
		} finally {
			lock.unlock();
		}
	}
	
	Set<Circuit> getCircuitsByFilter(CircuitFilter filter) {
		final Set<Circuit> result = new HashSet<Circuit>();
		final Set<CircuitImpl> circuits = new HashSet<CircuitImpl>();

		synchronized (activeCircuits) {
			// the filter might lock additional objects, causing a deadlock, so don't
			// call it inside the monitor
			circuits.addAll(activeCircuits);
		}

		for(CircuitImpl c: circuits) {
			if(filter == null || filter.filter(c)) {
				result.add(c);
			}
		}
		return result;
	}

	List<ExitCircuit> getRandomlyOrderedListOfExitCircuits() {
		final Set<Circuit> notDirectory = getCircuitsByFilter(new CircuitFilter() {
			
			public boolean filter(Circuit circuit) {
				final boolean exitType = circuit instanceof ExitCircuit;
				return exitType && !circuit.isMarkedForClose() && circuit.isConnected();
			}
		});
		final ArrayList<ExitCircuit> ac = new ArrayList<ExitCircuit>();
		for(Circuit c: notDirectory) {
			if(c instanceof ExitCircuit) {
				ac.add((ExitCircuit) c);
			}
		}
		final int sz = ac.size();
		for(int i = 0; i < sz; i++) {
			final ExitCircuit tmp = ac.get(i);
			final int swapIdx = random.nextInt(sz);
			ac.set(i, ac.get(swapIdx));
			ac.set(swapIdx, tmp);
		}
		return ac;
	}

	public Stream openExitStreamTo(String hostname, int port)
			throws InterruptedException, TimeoutException, OpenFailedException {
		if(hostname.endsWith(".onion")) {
			return hiddenServiceManager.getStreamTo(hostname, port);
		}
		validateHostname(hostname);
		circuitCreationTask.predictPort(port);
		return pendingExitStreams.openExitStream(hostname, port);
	}

	private void validateHostname(String hostname) throws OpenFailedException {
		maybeRejectInternalAddress(hostname);
		if(hostname.toLowerCase().endsWith(".onion")) {
			throw new OpenFailedException("Hidden services not supported");
		} else if(hostname.toLowerCase().endsWith(".exit")) {
			throw new OpenFailedException(".exit addresses are not supported");
		}
	}
	
	private void maybeRejectInternalAddress(String hostname) throws OpenFailedException {
		if(IPv4Address.isValidIPv4AddressString(hostname)) {
			maybeRejectInternalAddress(IPv4Address.createFromString(hostname));
		}
	}
	
	private void maybeRejectInternalAddress(IPv4Address address) throws OpenFailedException {
		final InetAddress inetAddress = address.toInetAddress();
		if(inetAddress.isSiteLocalAddress() && config.getClientRejectInternalAddress()) {
			throw new OpenFailedException("Rejecting stream target with internal address: "+ address);
		}
	}
	public Stream openExitStreamTo(IPv4Address address, int port)
			throws InterruptedException, TimeoutException, OpenFailedException {
		maybeRejectInternalAddress(address);
		circuitCreationTask.predictPort(port);
		return pendingExitStreams.openExitStream(address, port);
	}

	public List<StreamExitRequest> getPendingExitStreams() {
		return pendingExitStreams.getUnreservedPendingRequests();
	}

	public Stream openDirectoryStream() throws OpenFailedException, InterruptedException, TimeoutException {
		return openDirectoryStream(0);
	}

	public Stream openDirectoryStream(int purpose) throws OpenFailedException, InterruptedException {
		final int requestEventCode = purposeToEventCode(purpose, false);
		final int loadingEventCode = purposeToEventCode(purpose, true);
		
		int failCount = 0;
		while(failCount < OPEN_DIRECTORY_STREAM_RETRY_COUNT) {
			final DirectoryCircuit circuit = openDirectoryCircuit();
			if(requestEventCode > 0) {
				initializationTracker.notifyEvent(requestEventCode);
			}
			try {
				final Stream stream = circuit.openDirectoryStream(OPEN_DIRECTORY_STREAM_TIMEOUT, true);
				if(loadingEventCode > 0) {
					initializationTracker.notifyEvent(loadingEventCode);
				}
				return stream;
			} catch (StreamConnectFailedException e) {
				circuit.markForClose();
				failCount += 1;
			} catch (TimeoutException e) {
				circuit.markForClose();
			}
		}
		throw new OpenFailedException("Retry count exceeded opening directory stream");
	}

	public DirectoryCircuit openDirectoryCircuit() throws OpenFailedException {
		int failCount = 0;
		while(failCount < OPEN_DIRECTORY_STREAM_RETRY_COUNT) {
			final DirectoryCircuit circuit = CircuitImpl.createDirectoryCircuit(this);
			if(tryOpenCircuit(circuit, true, true)) {
				return circuit;
			}
			failCount += 1;
		}
		throw new OpenFailedException("Could not create circuit for directory stream");
	}
	
	private int purposeToEventCode(int purpose, boolean getLoadingEvent) {
		switch(purpose) {
		case DIRECTORY_PURPOSE_CONSENSUS:
			return getLoadingEvent ? Tor.BOOTSTRAP_STATUS_LOADING_STATUS : Tor.BOOTSTRAP_STATUS_REQUESTING_STATUS;
		case DIRECTORY_PURPOSE_CERTIFICATES:
			 return getLoadingEvent ? Tor.BOOTSTRAP_STATUS_LOADING_KEYS : Tor.BOOTSTRAP_STATUS_REQUESTING_KEYS;
		case DIRECTORY_PURPOSE_DESCRIPTORS:
			return getLoadingEvent ? Tor.BOOTSTRAP_STATUS_LOADING_DESCRIPTORS : Tor.BOOTSTRAP_STATUS_REQUESTING_DESCRIPTORS;
		default:
			return 0;
		}
	}

	private static class DirectoryCircuitResult implements CircuitBuildHandler {

		private boolean isFailed;
		
		public void connectionCompleted(Connection connection) {}
		public void nodeAdded(CircuitNode node) {}
		public void circuitBuildCompleted(Circuit circuit) {}
		
		public void connectionFailed(String reason) {
			isFailed = true;
		}

		public void circuitBuildFailed(String reason) {
			isFailed = true;
		}
		
		boolean isSuccessful() {
			return !isFailed;
		}
	}

	public void dashboardRender(DashboardRenderer renderer, PrintWriter writer, int flags) throws IOException {
		if((flags & DASHBOARD_CIRCUITS) == 0) {
			return;
		}
		renderer.renderComponent(writer, flags, connectionCache);
		renderer.renderComponent(writer, flags, circuitCreationTask.getCircuitPredictor());
		writer.println("[Circuit Manager]");
		writer.println();
		for(Circuit c: getCircuitsByFilter(null)) {
			renderer.renderComponent(writer, flags, c);
		}
	}

	public InternalCircuit getCleanInternalCircuit() throws InterruptedException {
		synchronized(cleanInternalCircuits) {
			try {
				requestedInternalCircuitCount += 1;
				while(cleanInternalCircuits.isEmpty()) {
					cleanInternalCircuits.wait();
				}
				return cleanInternalCircuits.remove();
			} finally {
				requestedInternalCircuitCount -= 1;
			}
		}
	}

	int getNeededCleanCircuitCount(boolean isPredicted) {
		synchronized (cleanInternalCircuits) {
			final int predictedCount = (isPredicted) ? 2 : 0;
			final int needed = Math.max(requestedInternalCircuitCount, predictedCount) - (pendingInternalCircuitCount + cleanInternalCircuits.size());
			if(needed < 0) {
				return 0;
			} else {
				return needed;
			}
		}
	}
	
	void incrementPendingInternalCircuitCount() {
		synchronized (cleanInternalCircuits) {
			pendingInternalCircuitCount += 1;
		}
	}
	
	void decrementPendingInternalCircuitCount() {
		synchronized (cleanInternalCircuits) {
			pendingInternalCircuitCount -= 1;
		}
	}

	void addCleanInternalCircuit(InternalCircuit circuit) {
		synchronized(cleanInternalCircuits) {
			pendingInternalCircuitCount -= 1;
			cleanInternalCircuits.add(circuit);
			cleanInternalCircuits.notifyAll();
		}
	}

	boolean isNtorEnabled() {
		switch(config.getUseNTorHandshake()) {
		case AUTO:
			return isNtorEnabledInConsensus();
		case FALSE:
			return false;
		case TRUE:
			return true;
		default:
			throw new IllegalArgumentException("getUseNTorHandshake() returned "+ config.getUseNTorHandshake());
		}
	}
	
	boolean isNtorEnabledInConsensus() {
		ConsensusDocument consensus = directory.getCurrentConsensusDocument();
		return (consensus != null) && (consensus.getUseNTorHandshake());
	}

	public DirectoryCircuit openDirectoryCircuitTo(List<Router> path) throws OpenFailedException {
		final DirectoryCircuit circuit = CircuitImpl.createDirectoryCircuitTo(this, path);
		if(!tryOpenCircuit(circuit, true, false)) {
			throw new OpenFailedException("Could not create directory circuit for path");
		}
		return circuit;
	}

	public ExitCircuit openExitCircuitTo(List<Router> path)	throws OpenFailedException {
		final ExitCircuit circuit = CircuitImpl.createExitCircuitTo(this, path);
		if(!tryOpenCircuit(circuit, false, false)) {
			throw new OpenFailedException("Could not create exit circuit for path");
		}
		return circuit;
	}

	public InternalCircuit openInternalCircuitTo(List<Router> path) throws OpenFailedException {
		final InternalCircuit circuit = CircuitImpl.createInternalCircuitTo(this, path);
		if(!tryOpenCircuit(circuit, false, false)) {
			throw new OpenFailedException("Could not create internal circuit for path");
		}
		return circuit;
	}
	
	private boolean tryOpenCircuit(Circuit circuit, boolean isDirectory, boolean trackInitialization) {
		final DirectoryCircuitResult result = new DirectoryCircuitResult();
		final CircuitCreationRequest req = new CircuitCreationRequest(pathChooser, circuit, result, isDirectory);
		final CircuitBuildTask task = new CircuitBuildTask(req, connectionCache, isNtorEnabled(), (trackInitialization) ? (initializationTracker) : (null));
		task.run();
		return result.isSuccessful();
	}
}
