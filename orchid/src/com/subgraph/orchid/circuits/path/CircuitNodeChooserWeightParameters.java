package com.subgraph.orchid.circuits.path;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Router;

class CircuitNodeChooserWeightParameters {
	private final static int VAR_WG = 0;
	private final static int VAR_WM = 1;
	private final static int VAR_WE = 2;
	private final static int VAR_WD = 3;
	private final static int VAR_WGB = 4;
	private final static int VAR_WMB = 5;
	private final static int VAR_WEB = 6;
	private final static int VAR_WDB = 7;
	private final static int VAR_COUNT = 8;
	
	private final static String ZERO = "zero";
	private final static String ONE = "one";
	
	static CircuitNodeChooserWeightParameters create(ConsensusDocument consensus, CircuitNodeChooser.WeightRule rule) {
		final double[] vars = new double[VAR_COUNT];
		final long scale = consensus.getWeightScaleParameter();
		final String[] tags = getTagsForWeightRule(rule);
		if(!populateVars(consensus, scale, tags, vars)) {
			return new CircuitNodeChooserWeightParameters(new double[VAR_COUNT], false);
		} else {
			return new CircuitNodeChooserWeightParameters(vars, true);
		}
	}
		
	static boolean populateVars(ConsensusDocument consensus, long scale, String[] tags, double[] vars) {
		for(int i = 0; i < VAR_COUNT; i++) {
			vars[i] = tagToVarValue(consensus, scale, tags[i]);
			if(vars[i] < 0.0) {
				return false;
			} else {
				vars[i] /= scale;
			}
		}
		return true;
	}

	static double tagToVarValue(ConsensusDocument consensus, long scale, String tag) {
		if(tag.equals(ZERO)) {
			return 0.0;
		} else if (tag.equals(ONE)) {
			return 1.0;
		} else {
			return consensus.getBandwidthWeight(tag);
		}
	}

	static String[] getTagsForWeightRule(CircuitNodeChooser.WeightRule rule) {
		switch(rule) {
		case WEIGHT_FOR_GUARD:
			return new String[] { 
					"Wgg", "Wgm", ZERO, "Wgd",
					"Wgb", "Wmb", "Web", "Wdb"};
			
		case WEIGHT_FOR_MID:
			return new String[] {
					"Wmg", "Wmm", "Wme", "Wmd",
					"Wgb", "Wmb", "Web", "Wdb"};
			
		case WEIGHT_FOR_EXIT:
			return new String[] {
					"Wee", "Wem", "Wed", "Weg",
					"Wgb", "Wmb", "Web", "Wdb"};
			
		case WEIGHT_FOR_DIR:
			return new String[] { 
					"Wbe", "Wbm", "Wbd", "Wbg",
					ONE, ONE, ONE, ONE };
			
		case NO_WEIGHTING:
			return new String[] {
					ONE, ONE, ONE, ONE,
					ONE, ONE, ONE, ONE };
		default:
			throw new IllegalArgumentException("Unhandled WeightRule type: "+ rule);
		}
	}

	private final double[] vars;
	private final boolean isValid;
	
	private CircuitNodeChooserWeightParameters(double[] vars, boolean isValid) {
		this.vars = vars;
		this.isValid = isValid;
	}
	
	boolean isValid() {
		return isValid;
	}

	double getWg() {
		return vars[VAR_WG];
	}

	double getWm() {
		return vars[VAR_WM];
	}

	double getWe() {
		return vars[VAR_WE];
	}

	double getWd() {
		return vars[VAR_WD];
	}
	
	double getWgb() {
		return vars[VAR_WGB];
	}
	double getWmb() {
		return vars[VAR_WMB];
	}
	double getWeb() {
		return vars[VAR_WEB];
	}
	double getWdb() {
		return vars[VAR_WDB];
	}
	
	double calculateWeightedBandwidth(Router router) {
		final long bw = kbToBytes(router.getEstimatedBandwidth());
		final double w = calculateWeight(
				router.isExit() && !router.isBadExit(), 
				router.isPossibleGuard(), 
				router.getDirectoryPort() != 0);
		return (w * bw) + 0.5;
	}
	
	long kbToBytes(long kb) {
		return (kb > (Long.MAX_VALUE / 1000) ? Long.MAX_VALUE : kb * 1000);
	}
	
	private double calculateWeight(boolean isExit, boolean isGuard, boolean isDir) {
		if(isGuard && isExit) {
			return (isDir) ? getWdb() * getWd() : getWd();
		} else if (isGuard) {
			return (isDir) ? getWgb() * getWg() : getWg();
		} else if (isExit) {
			return (isDir) ? getWeb() * getWe() : getWe();
		} else { // middle
			return (isDir) ? getWmb() * getWm() : getWm();
		}
	}
}
