package com.subgraph.orchid;

import com.subgraph.orchid.data.HexDigest;

public interface BridgeRouter extends Router {
	void setIdentity(HexDigest identity);
	void setDescriptor(RouterDescriptor descriptor);
}
