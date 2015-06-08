package com.subgraph.orchid.circuits.guards;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import com.subgraph.orchid.ConnectionCache;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.DirectoryDownloader;
import com.subgraph.orchid.GuardEntry;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Threading;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.path.CircuitNodeChooser;
import com.subgraph.orchid.circuits.path.CircuitNodeChooser.WeightRule;
import com.subgraph.orchid.circuits.path.RouterFilter;
import com.subgraph.orchid.crypto.TorRandom;

public class EntryGuards {
	private final static Logger logger = Logger.getLogger(EntryGuards.class.getName());
	
	private final static int MIN_USABLE_GUARDS = 2;
	private final static int NUM_ENTRY_GUARDS = 3;
	
	private final TorConfig config;
	private final TorRandom random;
	private final CircuitNodeChooser nodeChooser;
	private final ConnectionCache connectionCache;
	private final Directory directory;
	private final Set<GuardEntry> pendingProbes;
	
	private final Bridges bridges;
	private final Object lock;
	private final Executor executor;
	
	public EntryGuards(TorConfig config, ConnectionCache connectionCache, DirectoryDownloader directoryDownloader, Directory directory) {
		this.config = config;
		this.random = new TorRandom();
		this.nodeChooser = new CircuitNodeChooser(config, directory);
		this.connectionCache = connectionCache;
		this.directory = directory;
		this.pendingProbes = new HashSet<GuardEntry>();
		this.bridges = new Bridges(config, directoryDownloader);
		this.lock = new Object();
		this.executor = Threading.newPool("EntryGuards worker");
	}

	public boolean isUsingBridges() {
		return config.getUseBridges();
	}

	public Router chooseRandomGuard(Set<Router> excluded) throws InterruptedException {
		if(config.getUseBridges()) {
			return bridges.chooseRandomBridge(excluded);
		}
		
		/*
		 * path-spec 5.
		 * 
		 * When choosing the first hop of a circuit, Tor chooses at random from among the first 
		 * NumEntryGuards (default 3) usable guards on the list.  If there are not at least 2 
		 * usable guards on the list, Tor adds routers until there are, or until there are no 
		 * more usable routers to add.
		 */

		final List<Router> usableGuards = getMinimumUsableGuards(excluded, MIN_USABLE_GUARDS);
		final int n = Math.min(usableGuards.size(), NUM_ENTRY_GUARDS);
		return usableGuards.get(random.nextInt(n));
	}
	
	private List<Router> getMinimumUsableGuards(Set<Router> excluded, int minSize) throws InterruptedException {
		synchronized(lock) {
			testStatusOfAllGuards();
			while(true) {
				List<Router> usableGuards = getUsableGuardRouters(excluded);
				if(usableGuards.size() >= minSize) {
					return usableGuards;
				} else {
					maybeChooseNew(usableGuards.size(), minSize, getExcludedForChooseNew(excluded, usableGuards));
				}
				lock.wait(5000);
			}
		}
	}
	
	void probeConnectionSucceeded(GuardEntry entry) {
		synchronized (lock) {
			pendingProbes.remove(entry);
			if(entry.isAdded()) {
				retestProbeSucceeded(entry);
			} else {
				initialProbeSucceeded(entry);
			}
		}
	}
	
	void probeConnectionFailed(GuardEntry entry) {
		synchronized (lock) {
			pendingProbes.remove(entry);
			if(entry.isAdded()) {
				retestProbeFailed(entry);
			}
			lock.notifyAll();
		}
	}

	/* all methods below called holding 'lock' */
	
	private void retestProbeSucceeded(GuardEntry entry) {
		entry.clearDownSince();
	}
	
	private void initialProbeSucceeded(GuardEntry entry) {
		logger.fine("Probe connection to "+ entry.getRouterForEntry() + " succeeded.  Adding it as a new entry guard.");
		directory.addGuardEntry(entry);
		retestAllUnreachable();
	}
	
	private void retestProbeFailed(GuardEntry entry) {
		entry.markAsDown();
	}
	
	/*
	 * path-spec 5.
	 * 
	 * Additionally, Tor retries unreachable guards the first time it adds a new 
	 * guard to the list, since it is possible that the old guards were only marked 
	 * as unreachable because the network was unreachable or down.

	 */
	private void retestAllUnreachable() {
		for(GuardEntry e: directory.getGuardEntries()) {
			if(e.getDownSince() != null) {
				launchEntryProbe(e);
			}
		}
	}

	private void testStatusOfAllGuards() {
		for(GuardEntry entry: directory.getGuardEntries()) {
			if(isPermanentlyUnlisted(entry) || isExpired(entry)) {
				directory.removeGuardEntry(entry);
			} else if(needsUnreachableTest(entry)) {
				launchEntryProbe(entry);
			}
		}
	}
	
	private List<Router> getUsableGuardRouters(Set<Router> excluded) {
		List<Router> usableRouters = new ArrayList<Router>();
		for(GuardEntry entry: directory.getGuardEntries()) {
			addRouterIfUsableAndNotExcluded(entry, excluded, usableRouters);
		}
		return usableRouters;
	}
	
	private void addRouterIfUsableAndNotExcluded(GuardEntry entry, Set<Router> excluded, List<Router> routers) {
		if(entry.testCurrentlyUsable() && entry.getDownSince() == null) {
			final Router r = entry.getRouterForEntry();
			if(r != null && !excluded.contains(r)) {
				routers.add(r);
			}
		}
	}

	private Set<Router> getExcludedForChooseNew(Set<Router> excluded, List<Router> usable) {
		final Set<Router> set = new HashSet<Router>();
		set.addAll(excluded);
		set.addAll(usable);
		addPendingInitialConnections(set);
		return set;
	}

	private void addPendingInitialConnections(Set<Router> routerSet) {
		for(GuardEntry entry: pendingProbes) {
			if(!entry.isAdded()) {
				Router r = entry.getRouterForEntry();
				if(r != null) {
					routerSet.add(r);
				}
			}
		}
	}

	private void maybeChooseNew(int usableSize, int minSize, Set<Router> excluded) {
		int sz = usableSize + countPendingInitialProbes();
		while(sz < minSize) {	
			Router newGuard = chooseNewGuard(excluded);
			if(newGuard == null) {
				logger.warning("Need to add entry guards but no suitable guard routers are available");
				return;
			}
			logger.fine("Testing "+ newGuard + " as a new guard since we only have "+ usableSize + " usable guards");
			final GuardEntry entry = directory.createGuardEntryFor(newGuard);
			launchEntryProbe(entry);
			sz += 1;
		}
	}

	private int countPendingInitialProbes() {
		int count = 0;
		for(GuardEntry entry: pendingProbes) {
			if(!entry.isAdded()) {
				count += 1;
			}
		}
		return count;
	}
	
	private Router chooseNewGuard(final Set<Router> excluded) {
		return nodeChooser.chooseRandomNode(WeightRule.WEIGHT_FOR_GUARD, new RouterFilter() {
			public boolean filter(Router router) {
				return router.isValid() && router.isPossibleGuard() && router.isRunning() && !excluded.contains(router);
			}
		});
	}
	
	private void launchEntryProbe(GuardEntry entry) {
		if(!entry.testCurrentlyUsable() || pendingProbes.contains(entry)) {
			return;
		}
		pendingProbes.add(entry);
		executor.execute(new GuardProbeTask(connectionCache, this, entry));
	}
	
	/*
	 * path-spec 5.
	 * 
	 * If the guard is excluded because of its status in the networkstatuses for
	 * over 30 days, Tor removes it from the list entirely, preserving order.
	 */
	private boolean isPermanentlyUnlisted(GuardEntry entry) {
		final Date unlistedSince = entry.getUnlistedSince();
		if(unlistedSince == null || pendingProbes.contains(entry)) {
			return false;
		}
		final Date now = new Date();
		final long unlistedTime = now.getTime() - unlistedSince.getTime();
		return unlistedTime > THIRTY_DAYS; 
	}
	
	/*
	 * Expire guards after 60 days since creation time.
	 */
	private boolean isExpired(GuardEntry entry) {
		final Date createdAt = entry.getCreatedTime();
		final Date now = new Date();
		final long createdAgo = now.getTime() - createdAt.getTime();
		return createdAgo > SIXTY_DAYS;
	}

	private boolean needsUnreachableTest(GuardEntry entry) {
		final Date downSince = entry.getDownSince();
		if(downSince == null || !entry.testCurrentlyUsable()) {
			return false;
		}
		final Date now = new Date();
		final Date lastConnect = entry.getLastConnectAttempt();
		final long timeDown = now.getTime() - downSince.getTime();
		final long timeSinceLastRetest = (lastConnect == null) ? timeDown : (now.getTime() - lastConnect.getTime());
		
		return timeSinceLastRetest > getRetestInterval(timeDown);
	}
	
	private final static long ONE_HOUR = hoursToMs(1);
	private final static long FOUR_HOURS = hoursToMs(4);
	private final static long SIX_HOURS = hoursToMs(6);
	private final static long EIGHTEEN_HOURS = hoursToMs(18);
	private final static long THIRTYSIX_HOURS = hoursToMs(36);
	private final static long THREE_DAYS = daysToMs(3);
	private final static long SEVEN_DAYS = daysToMs(7);
	private final static long THIRTY_DAYS = daysToMs(30);
	private final static long SIXTY_DAYS = daysToMs(60);
	
	private static long hoursToMs(long n) {
		return TimeUnit.MILLISECONDS.convert(n, TimeUnit.HOURS);
	}
	private static long daysToMs(long n) {
		return TimeUnit.MILLISECONDS.convert(n, TimeUnit.DAYS);
	}
	/*
	 * path-spec 5.
	 * 
	 * If Tor fails to connect to an otherwise usable guard, it retries
	 * periodically: every hour for six hours, every 4 hours for 3 days, every
	 * 18 hours for a week, and every 36 hours thereafter. 
	 */
	
	private long getRetestInterval(long timeDown) {
		if(timeDown < SIX_HOURS) {
			return ONE_HOUR;
		} else if(timeDown < THREE_DAYS) {
			return FOUR_HOURS;
		} else if(timeDown < SEVEN_DAYS) {
			return EIGHTEEN_HOURS;
		} else {
			return THIRTYSIX_HOURS;
		}
	}
}
