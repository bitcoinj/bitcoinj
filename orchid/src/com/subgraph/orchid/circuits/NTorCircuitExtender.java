package com.subgraph.orchid.circuits;

import java.util.logging.Logger;

import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.crypto.TorNTorKeyAgreement;

public class NTorCircuitExtender {
	private final static Logger logger = Logger.getLogger(NTorCircuitExtender.class.getName());
	
	private final CircuitExtender extender;
	private final Router router;
	private final TorNTorKeyAgreement kex;
	
	public NTorCircuitExtender(CircuitExtender extender, Router router) {
		this.extender = extender;
		this.router = router;
		this.kex = new TorNTorKeyAgreement(router.getIdentityHash(), router.getNTorOnionKey());
	}

	CircuitNode extendTo() {
		final byte[] onion = kex.createOnionSkin();
		if(finalRouterSupportsExtend2()) {
			logger.fine("Extending circuit to "+ router.getNickname() + " with NTor inside RELAY_EXTEND2");
			return extendWithExtend2(onion);
		} else {
			logger.fine("Extending circuit to "+ router.getNickname() + " with NTor inside RELAY_EXTEND");
			return extendWithTunneledExtend(onion);
		}
	}
	
	private CircuitNode extendWithExtend2(byte[] onion) {
		final RelayCell cell = createExtend2Cell(onion);
		extender.sendRelayCell(cell);
		final RelayCell response = extender.receiveRelayResponse(RelayCell.RELAY_EXTENDED2, router);
		return processExtended2(response);
	}
	
	private CircuitNode extendWithTunneledExtend(byte[] onion) {
		final RelayCell cell = createExtendCell(onion, kex.getNtorCreateMagic());
		extender.sendRelayCell(cell);
		final RelayCell response = extender.receiveRelayResponse(RelayCell.RELAY_EXTENDED, router);
		return processExtended(response);
	}
	
	private boolean finalRouterSupportsExtend2() {
		return extender.getFinalRouter().getNTorOnionKey() != null;
	}
	
	private RelayCell createExtend2Cell(byte[] ntorOnionskin) {
		final RelayCell cell = extender.createRelayCell(RelayCell.RELAY_EXTEND2);

		cell.putByte(2);
			
		cell.putByte(0);
		cell.putByte(6);
		cell.putByteArray(router.getAddress().getAddressDataBytes());
		cell.putShort(router.getOnionPort());
			
		cell.putByte(2);
		cell.putByte(20);
		cell.putByteArray(router.getIdentityHash().getRawBytes());
			
		cell.putShort(0x0002);
		cell.putShort(ntorOnionskin.length);
		cell.putByteArray(ntorOnionskin);
		return cell;
	}
	
	private RelayCell createExtendCell(byte[] ntorOnionskin, byte[] ntorMagic) {
		final RelayCell cell = extender.createRelayCell(RelayCell.RELAY_EXTEND);
		cell.putByteArray(router.getAddress().getAddressDataBytes());
		cell.putShort(router.getOnionPort());
		final int paddingLength = CircuitExtender.TAP_ONIONSKIN_LEN - (ntorOnionskin.length + ntorMagic.length);
		final byte[] padding = new byte[paddingLength];
		cell.putByteArray(ntorMagic);
		cell.putByteArray(ntorOnionskin);
		cell.putByteArray(padding);
		cell.putByteArray(router.getIdentityHash().getRawBytes());
		return cell;
	}
	
	private CircuitNode processExtended(RelayCell cell) {
		byte[] payload = new byte[CircuitExtender.TAP_ONIONSKIN_REPLY_LEN];
		cell.getByteArray(payload);
		
		return processPayload(payload);
	}
	

	private CircuitNode processExtended2(RelayCell cell) {
		final int payloadLength = cell.getShort();
		if(payloadLength > cell.cellBytesRemaining()) {
			throw new TorException("Incorrect payload length value in RELAY_EXTENED2 cell");
		}
		byte[] payload = new byte[payloadLength];
		cell.getByteArray(payload);

		return processPayload(payload);
	}
	
	private CircuitNode processPayload(byte[] payload) {
		final byte[] keyMaterial = new byte[CircuitNodeCryptoState.KEY_MATERIAL_SIZE];
		final byte[] verifyDigest = new byte[TorMessageDigest.TOR_DIGEST_SIZE];
		if(!kex.deriveKeysFromHandshakeResponse(payload, keyMaterial, verifyDigest)) {
			return null;
		}
		return extender.createNewNode(router, keyMaterial, verifyDigest);
	}
}
