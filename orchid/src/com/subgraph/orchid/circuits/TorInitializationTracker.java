package com.subgraph.orchid.circuits;

import com.subgraph.orchid.Tor;
import com.subgraph.orchid.TorInitializationListener;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TorInitializationTracker {
	private final static Logger logger = Logger.getLogger(TorInitializationTracker.class.getName());
	private final static Map<Integer, String> messageMap = new HashMap<Integer, String>();
	
	static {
		messageMap.put(Tor.BOOTSTRAP_STATUS_STARTING, "Starting");
		messageMap.put(Tor.BOOTSTRAP_STATUS_CONN_DIR, "Connecting to directory server");
		messageMap.put(Tor.BOOTSTRAP_STATUS_HANDSHAKE_DIR, "Finishing handshake with directory server");
		messageMap.put(Tor.BOOTSTRAP_STATUS_ONEHOP_CREATE, "Establishing an encrypted directory connection");
		messageMap.put(Tor.BOOTSTRAP_STATUS_REQUESTING_STATUS, "Asking for network status consensus");
		messageMap.put(Tor.BOOTSTRAP_STATUS_LOADING_STATUS, "Loading network status consensus");
		messageMap.put(Tor.BOOTSTRAP_STATUS_REQUESTING_KEYS, "Asking for authority key certs");
		messageMap.put(Tor.BOOTSTRAP_STATUS_LOADING_KEYS, "Loading authority key certs");
		messageMap.put(Tor.BOOTSTRAP_STATUS_REQUESTING_DESCRIPTORS, "Asking for relay descriptors");
		messageMap.put(Tor.BOOTSTRAP_STATUS_LOADING_DESCRIPTORS, "Loading relay descriptors");
		messageMap.put(Tor.BOOTSTRAP_STATUS_CONN_OR, "Connecting to the Tor network");
		messageMap.put(Tor.BOOTSTRAP_STATUS_HANDSHAKE_OR, "Finished Handshake with first hop");
		messageMap.put(Tor.BOOTSTRAP_STATUS_CIRCUIT_CREATE, "Establishing a Tor circuit");
		messageMap.put(Tor.BOOTSTRAP_STATUS_DONE, "Done");
	}
	
	private final List<TorInitializationListener> listeners = new ArrayList<TorInitializationListener>();
	
	private final Object stateLock = new Object();
	private int bootstrapState = Tor.BOOTSTRAP_STATUS_STARTING;
	
	
	public void addListener(TorInitializationListener listener) {
		synchronized(listeners) {
			if(!listeners.contains(listener)) {
				listeners.add(listener);
			}
		}
	}
	
	public void removeListener(TorInitializationListener listener) {
		synchronized(listeners) {
			listeners.remove(listener);
		}
	}

	public int getBootstrapState() {
		return bootstrapState;
	}

	public void start() {
		synchronized (stateLock) {
			bootstrapState = Tor.BOOTSTRAP_STATUS_STARTING;
			notifyListeners(Tor.BOOTSTRAP_STATUS_STARTING);
		}
	}

	public void notifyEvent(int eventCode) {
		synchronized(stateLock) {
			if(eventCode <= bootstrapState || eventCode > 100) {
				return;
			}
			bootstrapState = eventCode;
			notifyListeners(eventCode);
		}
	}

	private void notifyListeners(int code) {
		final String message = getMessageForCode(code);
		for(TorInitializationListener listener: getListeners()) {
			try {
				listener.initializationProgress(message, code);
				if(code >= 100) {
					listener.initializationCompleted();
				}
			} catch(Exception e) {
				logger.log(Level.SEVERE, "Exception occurred in TorInitializationListener callback: "+ e.getMessage(), e);
			}
		}
	}

	private String getMessageForCode(int code) {
		if(messageMap.containsKey(code)) {
			return messageMap.get(code);
		} else {
			return "Unknown state";
		}
	}
	
	private List<TorInitializationListener> getListeners() {
		synchronized (listeners) {
			return new ArrayList<TorInitializationListener>(listeners);
		}
	}
	
}
