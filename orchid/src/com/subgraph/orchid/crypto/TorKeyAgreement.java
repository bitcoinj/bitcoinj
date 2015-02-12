package com.subgraph.orchid.crypto;

public interface TorKeyAgreement {
	byte[] createOnionSkin();
	boolean deriveKeysFromHandshakeResponse(byte[] handshakeResponse, byte[] keyMaterialOut, byte[] verifyHashOut);
}
