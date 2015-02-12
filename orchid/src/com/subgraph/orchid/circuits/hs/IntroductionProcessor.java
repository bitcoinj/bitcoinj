package com.subgraph.orchid.circuits.hs;

import java.nio.ByteBuffer;
import java.util.logging.Logger;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.Circuit;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.crypto.HybridEncryption;
import com.subgraph.orchid.crypto.TorPublicKey;

public class IntroductionProcessor {
	private final static Logger logger = Logger.getLogger(IntroductionProcessor.class.getName());
	private final static int INTRODUCTION_PROTOCOL_VERSION = 3;
	
	private final HiddenService hiddenService;
	private final Circuit introductionCircuit;
	private final IntroductionPoint introductionPoint;
	
	protected IntroductionProcessor(HiddenService hiddenService, Circuit introductionCircuit, IntroductionPoint introductionPoint) {
		this.hiddenService = hiddenService;
		this.introductionCircuit = introductionCircuit;
		this.introductionPoint = introductionPoint;
	}
	
	TorPublicKey getServiceKey() {
		return introductionPoint.getServiceKey();
	}
	
	boolean sendIntroduce(TorPublicKey permanentKey, byte[] publicKeyBytes, byte[] rendezvousCookie, Router rendezvousRouter) {
		final RelayCell introduceCell = introductionCircuit.createRelayCell(RelayCell.RELAY_COMMAND_INTRODUCE1, 0, introductionCircuit.getFinalCircuitNode());

		final byte[] payload = createIntroductionPayload(rendezvousRouter, publicKeyBytes, rendezvousCookie, permanentKey);
		final TorPublicKey serviceKey = introductionPoint.getServiceKey();
		introduceCell.putByteArray(serviceKey.getFingerprint().getRawBytes());
		introduceCell.putByteArray(payload);
		introductionCircuit.sendRelayCell(introduceCell);
		
		final RelayCell response = introductionCircuit.receiveRelayCell();
		if(response == null) {
			logger.fine("Timeout waiting for response to INTRODUCE1 cell");
			return false;
		} else if(response.getRelayCommand() != RelayCell.RELAY_COMMAND_INTRODUCE_ACK) {
			logger.info("Unexpected relay cell type received waiting for response to INTRODUCE1 cell: "+ response.getRelayCommand());
			return false;
		} else if(response.cellBytesRemaining() == 0) {
			return true;
		} else {
			logger.info("INTRODUCE_ACK indicates that introduction was not forwarded: "+ response.getByte());
			return false;
		} 
	}
	
	void markCircuitForClose() {
		introductionCircuit.markForClose();
	}

	private byte[] createIntroductionPayload(Router rendezvousRouter, byte[] publicKeyBytes, byte[] rendezvousCookie, TorPublicKey encryptionKey) {
		final ByteBuffer buffer = createIntroductionBuffer((int) (System.currentTimeMillis() / 1000), rendezvousRouter, rendezvousCookie, publicKeyBytes);
		return encryptIntroductionBuffer(buffer, encryptionKey);
	}
	
	private ByteBuffer createIntroductionBuffer(int timestamp, Router rr, byte[] cookie, byte[] dhPublic) {
		final ByteBuffer buffer = ByteBuffer.allocate(Cell.CELL_LEN);
		final byte[] rpAddress = rr.getAddress().getAddressDataBytes();
		final short rpPort = (short) rr.getOnionPort();
		final byte[] rpIdentity = rr.getIdentityHash().getRawBytes();
		final byte[] rpOnionKey = rr.getOnionKey().getRawBytes();
		
		buffer.put((byte) INTRODUCTION_PROTOCOL_VERSION);  // VER    Version byte: set to 3.        [1 octet]
		addAuthentication(buffer);
		//buffer.put((byte) 0);                              // AUTHT  The auth type that is used     [1 octet]
		buffer.putInt(timestamp);                          // TS     A timestamp                   [4 octets]
		buffer.put(rpAddress);                             // IP     Rendezvous point's address    [4 octets]
		buffer.putShort(rpPort);                           // PORT   Rendezvous point's OR port    [2 octets]
		buffer.put(rpIdentity);                            // ID     Rendezvous point identity ID [20 octets]
		buffer.putShort((short) rpOnionKey.length);		   // KLEN   Length of onion key           [2 octets]
		buffer.put(rpOnionKey); 		                   // KEY    Rendezvous point onion key [KLEN octets]
		buffer.put(cookie); 		                       // RC     Rendezvous cookie            [20 octets]
		buffer.put(dhPublic); 		                       // g^x    Diffie-Hellman data, part 1 [128 octets]
		
		return buffer;
	}
	
	private void addAuthentication(ByteBuffer buffer) {
		HSDescriptorCookie cookie = hiddenService.getAuthenticationCookie();
		if(cookie == null) {
			buffer.put((byte) 0);
		} else {
			buffer.put(cookie.getAuthTypeByte());
			buffer.putShort((short) cookie.getValue().length);
			buffer.put(cookie.getValue());
		}
	}

	private byte[] encryptIntroductionBuffer(ByteBuffer buffer, TorPublicKey key) {
		final int len = buffer.position();
		final byte[] payload = new byte[len];
		buffer.flip();
		buffer.get(payload);
		final HybridEncryption enc = new HybridEncryption();
		return enc.encrypt(payload, key);
	}
}
