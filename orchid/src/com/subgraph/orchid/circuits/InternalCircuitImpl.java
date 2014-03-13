package com.subgraph.orchid.circuits;

import java.util.List;
import java.util.concurrent.TimeoutException;

import com.subgraph.orchid.Circuit;
import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.DirectoryCircuit;
import com.subgraph.orchid.HiddenServiceCircuit;
import com.subgraph.orchid.InternalCircuit;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.StreamConnectFailedException;
import com.subgraph.orchid.circuits.path.CircuitPathChooser;
import com.subgraph.orchid.circuits.path.PathSelectionFailedException;

public class InternalCircuitImpl extends CircuitImpl implements InternalCircuit, DirectoryCircuit, HiddenServiceCircuit {

	private enum InternalType { UNUSED, HS_INTRODUCTION, HS_DIRECTORY, HS_CIRCUIT }
	
	private InternalType type;
	private boolean ntorEnabled;
	
	InternalCircuitImpl(CircuitManagerImpl circuitManager, List<Router> prechosenPath) {
		super(circuitManager, prechosenPath);
		this.type = InternalType.UNUSED;
		this.ntorEnabled = circuitManager.isNtorEnabled();
	}
	
	protected InternalCircuitImpl(CircuitManagerImpl circuitManager) {
		this(circuitManager, null);
	}
	
	@Override
	protected List<Router> choosePathForCircuit(CircuitPathChooser pathChooser)
			throws InterruptedException, PathSelectionFailedException {
		return pathChooser.chooseInternalPath();
	}
	

	public Circuit cannibalizeToIntroductionPoint(Router target) {
		cannibalizeTo(target);
		type = InternalType.HS_INTRODUCTION;
		return this;
	}

	private void cannibalizeTo(Router target) {
		if(type != InternalType.UNUSED) {
			throw new IllegalStateException("Cannot cannibalize internal circuit with type "+ type);
			
		}
		final CircuitExtender extender = new CircuitExtender(this, ntorEnabled);
		extender.extendTo(target);
	}
	
	public Stream openDirectoryStream(long timeout, boolean autoclose) throws InterruptedException, TimeoutException, StreamConnectFailedException {
		if(type != InternalType.HS_DIRECTORY) {
			throw new IllegalStateException("Cannot open directory stream on internal circuit with type "+ type);
		}
		final StreamImpl stream = createNewStream();
		try {
			stream.openDirectory(timeout);
			return stream;
		} catch (Exception e) {
			removeStream(stream);
			return processStreamOpenException(e);
		}
	}

	
	public DirectoryCircuit cannibalizeToDirectory(Router target) {
		cannibalizeTo(target);
		type = InternalType.HS_DIRECTORY;
		return this;
	}


	public HiddenServiceCircuit connectHiddenService(CircuitNode node) {
		if(type != InternalType.UNUSED) {
			throw new IllegalStateException("Cannot connect hidden service from internal circuit type "+ type);
		}
		appendNode(node);
		type = InternalType.HS_CIRCUIT;
		return this;
	}

	public Stream openStream(int port, long timeout) 
			throws InterruptedException, TimeoutException, StreamConnectFailedException {
		if(type != InternalType.HS_CIRCUIT) {
			throw new IllegalStateException("Cannot open stream to hidden service from internal circuit type "+ type);
		}
		final StreamImpl stream = createNewStream();
		try {
			stream.openExit("", port, timeout);
			return stream;
		} catch (Exception e) {
			removeStream(stream);
			return processStreamOpenException(e);
		}
	}


	@Override
	protected String getCircuitTypeLabel() {
		switch(type) {
		case HS_CIRCUIT:
			return "Hidden Service";
		case HS_DIRECTORY:
			return "HS Directory";
		case HS_INTRODUCTION:
			return "HS Introduction";
		case UNUSED:
			return "Internal";
		default:
			return "(null)";
		}
	}
}
