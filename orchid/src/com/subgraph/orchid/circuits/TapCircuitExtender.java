package com.subgraph.orchid.circuits;

import java.util.logging.Logger;

import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.crypto.TorTapKeyAgreement;

public class TapCircuitExtender {
	private final static Logger logger = Logger.getLogger(TapCircuitExtender.class.getName());
	
	private final CircuitExtender extender;
	private final TorTapKeyAgreement kex;
	private final Router router;
	
	public TapCircuitExtender(CircuitExtender extender, Router router) {
		this.extender = extender;
		this.router = router;
		this.kex = new TorTapKeyAgreement(router.getOnionKey());
	}

	public CircuitNode extendTo() {
		logger.fine("Extending to "+ router.getNickname() + " with TAP");
		final RelayCell cell = createRelayExtendCell();
		extender.sendRelayCell(cell);
		final RelayCell response = extender.receiveRelayResponse(RelayCell.RELAY_EXTENDED, router);
		if(response == null) {
			return null;
		}
		return processExtendResponse(response);
	}

	private CircuitNode processExtendResponse(RelayCell response) {
		final byte[] handshakeResponse = new byte[TorTapKeyAgreement.DH_LEN + TorMessageDigest.TOR_DIGEST_SIZE];
		response.getByteArray(handshakeResponse);
		
		final byte[] keyMaterial = new byte[CircuitNodeCryptoState.KEY_MATERIAL_SIZE];
		final byte[] verifyDigest = new byte[TorMessageDigest.TOR_DIGEST_SIZE];
		if(!kex.deriveKeysFromHandshakeResponse(handshakeResponse, keyMaterial, verifyDigest)) {
			return null;
		}
		return extender.createNewNode(router, keyMaterial, verifyDigest);
	}

	private RelayCell createRelayExtendCell() {
		final RelayCell cell = extender.createRelayCell(RelayCell.RELAY_EXTEND);
		cell.putByteArray(router.getAddress().getAddressDataBytes());
		cell.putShort(router.getOnionPort());
		cell.putByteArray(kex.createOnionSkin());
		cell.putByteArray(router.getIdentityHash().getRawBytes());
		return cell;
	}
}
