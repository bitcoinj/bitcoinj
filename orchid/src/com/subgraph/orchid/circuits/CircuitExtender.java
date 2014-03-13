package com.subgraph.orchid.circuits;

import java.util.logging.Logger;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.cells.CellImpl;
import com.subgraph.orchid.circuits.cells.RelayCellImpl;
import com.subgraph.orchid.crypto.TorCreateFastKeyAgreement;
import com.subgraph.orchid.crypto.TorKeyAgreement;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.crypto.TorStreamCipher;

public class CircuitExtender {
	private final static Logger logger = Logger.getLogger(CircuitExtender.class.getName());
	
	private final static int DH_BYTES = 1024 / 8;
	private final static int PKCS1_OAEP_PADDING_OVERHEAD = 42;
	private final static int CIPHER_KEY_LEN = TorStreamCipher.KEY_LEN;
	final static int TAP_ONIONSKIN_LEN = PKCS1_OAEP_PADDING_OVERHEAD + CIPHER_KEY_LEN + DH_BYTES;
	final static int TAP_ONIONSKIN_REPLY_LEN = DH_BYTES + TorMessageDigest.TOR_DIGEST_SIZE;
	
	
	private final CircuitImpl circuit;
	private final boolean ntorEnabled;
	
	
	CircuitExtender(CircuitImpl circuit, boolean ntorEnabled) {
		this.circuit = circuit;
		this.ntorEnabled = ntorEnabled;
	}
	
	
	CircuitNode createFastTo(Router targetRouter) {
		logger.fine("Creating 'fast' to "+ targetRouter);
		final TorCreateFastKeyAgreement kex = new TorCreateFastKeyAgreement();
		sendCreateFastCell(kex);
		return receiveAndProcessCreateFastResponse(targetRouter, kex);
	}

	private void sendCreateFastCell(TorCreateFastKeyAgreement kex) {
		final Cell cell = CellImpl.createCell(circuit.getCircuitId(), Cell.CREATE_FAST);
		cell.putByteArray(kex.createOnionSkin());
		circuit.sendCell(cell);
	}
	
	private CircuitNode receiveAndProcessCreateFastResponse(Router targetRouter, TorKeyAgreement kex) {
		final Cell cell = circuit.receiveControlCellResponse();
		if(cell == null) {
			throw new TorException("Timeout building circuit waiting for CREATE_FAST response from "+ targetRouter);
		}

		return processCreatedFastCell(targetRouter, cell, kex);
	}
	
	private CircuitNode processCreatedFastCell(Router targetRouter, Cell cell, TorKeyAgreement kex) {
		final byte[] payload = new byte[TorMessageDigest.TOR_DIGEST_SIZE * 2];
		final byte[] keyMaterial = new byte[CircuitNodeCryptoState.KEY_MATERIAL_SIZE];
		final byte[] verifyHash = new byte[TorMessageDigest.TOR_DIGEST_SIZE];
		cell.getByteArray(payload);
		if(!kex.deriveKeysFromHandshakeResponse(payload, keyMaterial, verifyHash)) {
			// XXX
			return null;
		}
		final CircuitNode node = CircuitNodeImpl.createFirstHop(targetRouter, keyMaterial, verifyHash);
		circuit.appendNode(node);
		return node;
	}
	
	CircuitNode extendTo(Router targetRouter) {
		if(circuit.getCircuitLength() == 0) {
			throw new TorException("Cannot EXTEND an empty circuit");
		}
		
		if(useNtor(targetRouter)) {
			final NTorCircuitExtender nce = new NTorCircuitExtender(this, targetRouter);
			return nce.extendTo();
		} else {
			final TapCircuitExtender tce = new TapCircuitExtender(this, targetRouter);
			return tce.extendTo();
		}
	}

	private boolean useNtor(Router targetRouter) {
		return ntorEnabled && targetRouter.getNTorOnionKey() != null;
	}
	
	private void logProtocolViolation(String sourceName, Router targetRouter) {
		final String version = (targetRouter == null) ? "(none)" : targetRouter.getVersion();
		final String targetName = (targetRouter == null) ? "(none)" : targetRouter.getNickname();
		logger.warning("Protocol error extending circuit from ("+ sourceName +") to ("+ targetName +") [version: "+ version +"]");
	}

	private String nodeToName(CircuitNode node) {
		if(node == null || node.getRouter() == null) {
			return "(null)";
		}
		final Router router = node.getRouter();
		return router.getNickname();
	}


	public void sendRelayCell(RelayCell cell) {
		circuit.sendRelayCell(cell);
	}


	public RelayCell receiveRelayResponse(int expectedCommand, Router extendTarget) {
		final RelayCell cell = circuit.receiveRelayCell();
		if(cell == null) {
			throw new TorException("Timeout building circuit");
		}
		final int command = cell.getRelayCommand();
		if(command == RelayCell.RELAY_TRUNCATED) {
			final int code = cell.getByte() & 0xFF;
			final String msg = CellImpl.errorToDescription(code);
			final String source = nodeToName(cell.getCircuitNode());
			if(code == Cell.ERROR_PROTOCOL) {
				logProtocolViolation(source, extendTarget);
			}
			throw new TorException("Error from ("+ source +") while extending to ("+ extendTarget.getNickname() + "): "+ msg);
		} else if(command != expectedCommand) {
			final String expected = RelayCellImpl.commandToDescription(expectedCommand);
			final String received = RelayCellImpl.commandToDescription(command);
			throw new TorException("Received incorrect extend response, expecting "+ expected + " but received "+ received);
		} else {
			return cell;
		}
	}


	public CircuitNode createNewNode(Router r, byte[] keyMaterial, byte[] verifyDigest) {
		final CircuitNode node = CircuitNodeImpl.createNode(r, circuit.getFinalCircuitNode(), keyMaterial, verifyDigest);
		logger.fine("Adding new circuit node for "+ r.getNickname());
		circuit.appendNode(node);
		return node;

	}

	public RelayCell createRelayCell(int command) {
		return new RelayCellImpl(circuit.getFinalCircuitNode(), circuit.getCircuitId(), 0, command, true);
	}
	
	Router getFinalRouter() {
		final CircuitNode node = circuit.getFinalCircuitNode();
		if(node != null) {
			return node.getRouter();
		} else {
			return null;
		}
	}
}
