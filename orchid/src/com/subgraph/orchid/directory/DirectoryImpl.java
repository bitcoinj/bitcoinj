package com.subgraph.orchid.directory;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.ConsensusDocument.ConsensusFlavor;
import com.subgraph.orchid.ConsensusDocument.RequiredCertificate;
import com.subgraph.orchid.Descriptor;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.DirectoryServer;
import com.subgraph.orchid.DirectoryStore;
import com.subgraph.orchid.DirectoryStore.CacheFile;
import com.subgraph.orchid.GuardEntry;
import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.RouterDescriptor;
import com.subgraph.orchid.RouterMicrodescriptor;
import com.subgraph.orchid.RouterStatus;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorConfig.AutoBoolValue;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.RandomSet;
import com.subgraph.orchid.directory.parsing.DocumentParser;
import com.subgraph.orchid.directory.parsing.DocumentParserFactory;
import com.subgraph.orchid.directory.parsing.DocumentParsingResult;
import com.subgraph.orchid.events.Event;
import com.subgraph.orchid.events.EventHandler;
import com.subgraph.orchid.events.EventManager;

public class DirectoryImpl implements Directory {
	private final static Logger logger = Logger.getLogger(DirectoryImpl.class.getName());

	private final Object loadLock = new Object();
	private boolean isLoaded = false;
	
	private final DirectoryStore store;
	private final TorConfig config;
	private final StateFile stateFile;
	private final DescriptorCache<RouterMicrodescriptor> microdescriptorCache;
	private final DescriptorCache<RouterDescriptor> basicDescriptorCache;
	
	private final Map<HexDigest, RouterImpl> routersByIdentity;
	private final Map<String, RouterImpl> routersByNickname;
	private final RandomSet<RouterImpl> directoryCaches;
	private final Set<ConsensusDocument.RequiredCertificate> requiredCertificates;
	private boolean haveMinimumRouterInfo;
	private boolean needRecalculateMinimumRouterInfo;
	private final EventManager consensusChangedManager;
	private final TorRandom random;
	private final static DocumentParserFactory parserFactory = new DocumentParserFactoryImpl();
	
	private ConsensusDocument currentConsensus;
	private ConsensusDocument consensusWaitingForCertificates;

	public DirectoryImpl(TorConfig config, DirectoryStore customDirectoryStore) {
		store = (customDirectoryStore == null) ? (new DirectoryStoreImpl(config)) : (customDirectoryStore);
		this.config = config;
		stateFile = new StateFile(store, this);
		microdescriptorCache = createMicrodescriptorCache(store);
		basicDescriptorCache = createBasicDescriptorCache(store);	
		routersByIdentity = new HashMap<HexDigest, RouterImpl>();
		routersByNickname = new HashMap<String, RouterImpl>();
		directoryCaches = new RandomSet<RouterImpl>();
		requiredCertificates = new HashSet<ConsensusDocument.RequiredCertificate>();
		consensusChangedManager = new EventManager();
		random = new TorRandom();
	}

	private static DescriptorCache<RouterMicrodescriptor> createMicrodescriptorCache(DirectoryStore store) {
		return new DescriptorCache<RouterMicrodescriptor>(store, CacheFile.MICRODESCRIPTOR_CACHE, CacheFile.MICRODESCRIPTOR_JOURNAL) {
			@Override
			protected DocumentParser<RouterMicrodescriptor> createDocumentParser(ByteBuffer buffer) {
				return parserFactory.createRouterMicrodescriptorParser(buffer);
			}
		};
	}

	private static DescriptorCache<RouterDescriptor> createBasicDescriptorCache(DirectoryStore store) {
		return new DescriptorCache<RouterDescriptor>(store, CacheFile.DESCRIPTOR_CACHE, CacheFile.DESCRIPTOR_JOURNAL) {
			@Override
			protected DocumentParser<RouterDescriptor> createDocumentParser(ByteBuffer buffer) {
				return parserFactory.createRouterDescriptorParser(buffer, false);
			}
		};
	}

	public synchronized boolean haveMinimumRouterInfo() {
		if(needRecalculateMinimumRouterInfo) {
			checkMinimumRouterInfo();
		}
		return haveMinimumRouterInfo;
	}

	private synchronized void checkMinimumRouterInfo() {
		if(currentConsensus == null || !currentConsensus.isLive()) {
			needRecalculateMinimumRouterInfo = true;
			haveMinimumRouterInfo = false;
			return;
		}

		int routerCount = 0;
		int descriptorCount = 0;
		for(Router r: routersByIdentity.values()) {
			routerCount++;
			if(!r.isDescriptorDownloadable())
				descriptorCount++;
		}
		needRecalculateMinimumRouterInfo = false;
		haveMinimumRouterInfo = (descriptorCount * 4 > routerCount);
	}

	public void loadFromStore() {
		logger.info("Loading cached network information from disk");
		
		synchronized(loadLock) {
			if(isLoaded) {
				return;
			}
			boolean useMicrodescriptors = config.getUseMicrodescriptors() != AutoBoolValue.FALSE;
			last = System.currentTimeMillis();
			logger.info("Loading certificates");
			loadCertificates(store.loadCacheFile(CacheFile.CERTIFICATES));
			logElapsed();
			
			logger.info("Loading consensus");
			loadConsensus(store.loadCacheFile(useMicrodescriptors ? CacheFile.CONSENSUS_MICRODESC : CacheFile.CONSENSUS));
			logElapsed();
			
			if(!useMicrodescriptors) {
				logger.info("Loading descriptors");
				basicDescriptorCache.initialLoad();
			} else {
				logger.info("Loading microdescriptor cache");
				microdescriptorCache.initialLoad();
			}
			needRecalculateMinimumRouterInfo = true;
			logElapsed();
			
			logger.info("loading state file");
			stateFile.parseBuffer(store.loadCacheFile(CacheFile.STATE));
			logElapsed();
			
			isLoaded = true;
			loadLock.notifyAll();
		}
	}

	public void close() {
		basicDescriptorCache.shutdown();
		microdescriptorCache.shutdown();
	}

	private long last = 0;
	private void logElapsed() {
		final long now = System.currentTimeMillis();
		final long elapsed =  now - last;
		last = now;
		logger.fine("Loaded in "+ elapsed + " ms.");
	}

	private void loadCertificates(ByteBuffer buffer) {
		final DocumentParser<KeyCertificate> parser = parserFactory.createKeyCertificateParser(buffer);
		final DocumentParsingResult<KeyCertificate> result = parser.parse();
		if(testResult(result, "certificates")) {
			for(KeyCertificate cert: result.getParsedDocuments()) {
				addCertificate(cert);
			}
		}
	}
	
	private void loadConsensus(ByteBuffer buffer) {
		final DocumentParser<ConsensusDocument> parser = parserFactory.createConsensusDocumentParser(buffer);
		final DocumentParsingResult<ConsensusDocument> result = parser.parse();
		if(testResult(result, "consensus")) {
			addConsensusDocument(result.getDocument(), true);
		}
	}

	private boolean testResult(DocumentParsingResult<?> result, String type) {
		if(result.isOkay()) {
			return true;
		} else if(result.isError()) {
			logger.warning("Parsing error loading "+ type + " : "+ result.getMessage());
		} else if(result.isInvalid()) {
			logger.warning("Problem loading "+ type + " : "+ result.getMessage());
		} else {
			logger.warning("Unknown problem loading "+ type);
		}
		return false;
	}
	
	public void waitUntilLoaded() {
		synchronized (loadLock) {
			while(!isLoaded) {
				try {
					loadLock.wait();
				} catch (InterruptedException e) {
					logger.warning("Thread interrupted while waiting for directory to load from disk");
				}
			}
		}
	}

	public Collection<DirectoryServer> getDirectoryAuthorities() {
		return TrustedAuthorities.getInstance().getAuthorityServers();
	}

	public DirectoryServer getRandomDirectoryAuthority() {
		final List<DirectoryServer> servers = TrustedAuthorities.getInstance().getAuthorityServers();
		final int idx = random.nextInt(servers.size());
		return servers.get(idx);
	}

	public Set<ConsensusDocument.RequiredCertificate> getRequiredCertificates() {
		return new HashSet<ConsensusDocument.RequiredCertificate>(requiredCertificates);
	}
	
	public void addCertificate(KeyCertificate certificate) {
		synchronized(TrustedAuthorities.getInstance()) {
			final boolean wasRequired = removeRequiredCertificate(certificate);
			final DirectoryServer as = TrustedAuthorities.getInstance().getAuthorityServerByIdentity(certificate.getAuthorityFingerprint());
			if(as == null) {
				logger.warning("Certificate read for unknown directory authority with identity: "+ certificate.getAuthorityFingerprint());
				return;
			}
			as.addCertificate(certificate);
			
			if(consensusWaitingForCertificates != null && wasRequired) {
				
				switch(consensusWaitingForCertificates.verifySignatures()) {
				case STATUS_FAILED:
					consensusWaitingForCertificates = null;
					return;
					
				case STATUS_VERIFIED:
					addConsensusDocument(consensusWaitingForCertificates, false);
					consensusWaitingForCertificates = null;
					return;

				case STATUS_NEED_CERTS:
					requiredCertificates.addAll(consensusWaitingForCertificates.getRequiredCertificates());
					return;
				}
			}
		}
	}
	
	private boolean removeRequiredCertificate(KeyCertificate certificate) {
		final Iterator<RequiredCertificate> it = requiredCertificates.iterator();
		while(it.hasNext()) {
			RequiredCertificate r = it.next();
			if(r.getSigningKey().equals(certificate.getAuthoritySigningKey().getFingerprint())) {
				it.remove();
				return true;
			}
		}
		return false;
	}
	
	public void storeCertificates() {
		synchronized(TrustedAuthorities.getInstance()) {
			final List<KeyCertificate> certs = new ArrayList<KeyCertificate>();
			for(DirectoryServer ds: TrustedAuthorities.getInstance().getAuthorityServers()) {
				certs.addAll(ds.getCertificates());
			}
			store.writeDocumentList(CacheFile.CERTIFICATES, certs);
		}
	}

	public void addRouterDescriptors(List<RouterDescriptor> descriptors) {
		basicDescriptorCache.addDescriptors(descriptors);
		needRecalculateMinimumRouterInfo = true;
	}

	public synchronized void addConsensusDocument(ConsensusDocument consensus, boolean fromCache) {
		if(consensus.equals(currentConsensus))
			return;

		if(currentConsensus != null && consensus.getValidAfterTime().isBefore(currentConsensus.getValidAfterTime())) {
			logger.warning("New consensus document is older than current consensus document");
			return;
		}

		synchronized(TrustedAuthorities.getInstance()) {
			switch(consensus.verifySignatures()) {
			case STATUS_FAILED:
				logger.warning("Unable to verify signatures on consensus document, discarding...");
				return;
				
			case STATUS_NEED_CERTS:
				consensusWaitingForCertificates = consensus;
				requiredCertificates.addAll(consensus.getRequiredCertificates());
				return;

			case STATUS_VERIFIED:
				break;
			}
			requiredCertificates.addAll(consensus.getRequiredCertificates());
		
		}
		final Map<HexDigest, RouterImpl> oldRouterByIdentity = new HashMap<HexDigest, RouterImpl>(routersByIdentity);

		clearAll();

		for(RouterStatus status: consensus.getRouterStatusEntries()) {
			if(status.hasFlag("Running") && status.hasFlag("Valid")) {
				final RouterImpl router = updateOrCreateRouter(status, oldRouterByIdentity);
				addRouter(router);
				classifyRouter(router);
			}
			final Descriptor d = getDescriptorForRouterStatus(status, consensus.getFlavor() == ConsensusFlavor.MICRODESC);
			if(d != null) {
				d.setLastListed(consensus.getValidAfterTime().getTime());
			}
		}
		
		logger.fine("Loaded "+ routersByIdentity.size() +" routers from consensus document");
		currentConsensus = consensus;
		
		if(!fromCache) {
			storeCurrentConsensus();
		}
		consensusChangedManager.fireEvent(new Event() {});
	}

	private void storeCurrentConsensus() {
		if(currentConsensus != null) {
			if(currentConsensus.getFlavor() == ConsensusFlavor.MICRODESC) {
				store.writeDocument(CacheFile.CONSENSUS_MICRODESC, currentConsensus);
			} else {
				store.writeDocument(CacheFile.CONSENSUS, currentConsensus);
			}
		}
	}

	private Descriptor getDescriptorForRouterStatus(RouterStatus rs, boolean isMicrodescriptor) {
		if(isMicrodescriptor) {
			return microdescriptorCache.getDescriptor(rs.getMicrodescriptorDigest());
		} else {
			return basicDescriptorCache.getDescriptor(rs.getDescriptorDigest());
		}
	}
	
	private RouterImpl updateOrCreateRouter(RouterStatus status, Map<HexDigest, RouterImpl> knownRouters) {
		final RouterImpl router = knownRouters.get(status.getIdentity());
		if(router == null)
			return RouterImpl.createFromRouterStatus(this, status);
		router.updateStatus(status);
		return router;
	}

	private void clearAll() {
		routersByIdentity.clear();
		routersByNickname.clear();
		directoryCaches.clear();
	}

	private void classifyRouter(RouterImpl router) {
		if(isValidDirectoryCache(router)) {
			directoryCaches.add(router);
		} else {
			directoryCaches.remove(router);
		}
	}

	private boolean isValidDirectoryCache(RouterImpl router) {
		if(router.getDirectoryPort() == 0)
			return false;
		if(router.hasFlag("BadDirectory"))
			return false;
		return router.hasFlag("V2Dir");
	}

	private void addRouter(RouterImpl router) {
		routersByIdentity.put(router.getIdentityHash(), router);
		addRouterByNickname(router);
	}

	private void addRouterByNickname(RouterImpl router) {
		final String name = router.getNickname();
		if(name == null || name.equals("Unnamed"))
			return;
		if(routersByNickname.containsKey(router.getNickname())) {
			//logger.warn("Duplicate router nickname: "+ router.getNickname());
			return;
		}
		routersByNickname.put(name, router);
	}

	public synchronized void addRouterMicrodescriptors(List<RouterMicrodescriptor> microdescriptors) {
		microdescriptorCache.addDescriptors(microdescriptors);
		needRecalculateMinimumRouterInfo = true;
	}

	synchronized public List<Router> getRoutersWithDownloadableDescriptors() {
		waitUntilLoaded();
		final List<Router> routers = new ArrayList<Router>();
		for(RouterImpl router: routersByIdentity.values()) {
			if(router.isDescriptorDownloadable())
				routers.add(router);
		}

		for(int i = 0; i < routers.size(); i++) {
			final Router a = routers.get(i);
			final int swapIdx = random.nextInt(routers.size());
			final Router b = routers.get(swapIdx);
			routers.set(i, b);
			routers.set(swapIdx, a);
		}

		return routers;
	}

	public ConsensusDocument getCurrentConsensusDocument() {
		return currentConsensus;
	}

	public boolean hasPendingConsensus() {
		synchronized (TrustedAuthorities.getInstance()) {
			return consensusWaitingForCertificates != null;	
		}
	}

	public void registerConsensusChangedHandler(EventHandler handler) {
		consensusChangedManager.addListener(handler);
	}

	public void unregisterConsensusChangedHandler(EventHandler handler) {
		consensusChangedManager.removeListener(handler);
	}

	public Router getRouterByName(String name) {
		if(name.equals("Unnamed")) {
			return null;
		}
		if(name.length() == 41 && name.charAt(0) == '$') {
			try {
				final HexDigest identity = HexDigest.createFromString(name.substring(1));
				return getRouterByIdentity(identity);
			} catch (Exception e) {
				return null;
			}
		}
		waitUntilLoaded();
		return routersByNickname.get(name);
	}

	public Router getRouterByIdentity(HexDigest identity) {
		waitUntilLoaded();
		synchronized (routersByIdentity) {
			return routersByIdentity.get(identity);
		}
	}

	public List<Router> getRouterListByNames(List<String> names) {
		waitUntilLoaded();
		final List<Router> routers = new ArrayList<Router>();
		for(String n: names) {
			final Router r = getRouterByName(n);
			if(r == null)
				throw new TorException("Could not find router named: "+ n);
			routers.add(r);
		}
		return routers;
	}

	public List<Router> getAllRouters() {
		waitUntilLoaded();
		synchronized(routersByIdentity) {
			return new ArrayList<Router>(routersByIdentity.values());
		}
	}

	public GuardEntry createGuardEntryFor(Router router) {
		waitUntilLoaded();
		return stateFile.createGuardEntryFor(router);
	}

	public List<GuardEntry> getGuardEntries() {
		waitUntilLoaded();
		return stateFile.getGuardEntries();
	}

	public void removeGuardEntry(GuardEntry entry) {
		waitUntilLoaded();
		stateFile.removeGuardEntry(entry);
	}

	public void addGuardEntry(GuardEntry entry) {
		waitUntilLoaded();
		stateFile.addGuardEntry(entry);
	}

	public RouterMicrodescriptor getMicrodescriptorFromCache(HexDigest descriptorDigest) {
		return microdescriptorCache.getDescriptor(descriptorDigest);
	}


	public RouterDescriptor getBasicDescriptorFromCache(HexDigest descriptorDigest) {
		return basicDescriptorCache.getDescriptor(descriptorDigest);
	}
}
