package com.subgraph.orchid;

public interface InternalCircuit extends Circuit {
	DirectoryCircuit cannibalizeToDirectory(Router target);
	Circuit cannibalizeToIntroductionPoint(Router target);
	HiddenServiceCircuit connectHiddenService(CircuitNode node);
}
