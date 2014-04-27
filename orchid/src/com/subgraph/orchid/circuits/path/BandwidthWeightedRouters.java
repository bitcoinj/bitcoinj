package com.subgraph.orchid.circuits.path;

import java.util.ArrayList;
import java.util.List;

import com.subgraph.orchid.Router;
import com.subgraph.orchid.crypto.TorRandom;

public class BandwidthWeightedRouters {
	private static class WeightedRouter {
		private final Router router;
		private boolean isUnknown;
		private double weightedBandwidth;
		private long scaledBandwidth;
		
		WeightedRouter(Router router, double bw) {
			this.router = router;
			this.weightedBandwidth = bw;
		}
				
		void scaleBandwidth(double scaleFactor) {
			scaledBandwidth = Math.round(weightedBandwidth * scaleFactor);
		}
	}
	
	private final static long MAX_SCALE = Long.MAX_VALUE / 4;
	private final static double EPSILON = 0.1;
	private final List<WeightedRouter> weightedRouters = new ArrayList<WeightedRouter>();
	private final TorRandom random = new TorRandom();
	
	private double totalExitBw;
	private double totalNonExitBw;
	private double totalGuardBw;
	
	private boolean isScaled;
	private int unknownCount;
	
	void addRouter(Router router, double weightedBandwidth) {
		weightedRouters.add(new WeightedRouter(router, weightedBandwidth));
		adjustTotals(router, weightedBandwidth);
		isScaled = false;
	}
	
	
	boolean isTotalBandwidthZero() {
		return getTotalBandwidth() < EPSILON;
	}

	double getTotalBandwidth() {
		return totalExitBw + totalNonExitBw;
	}
	
	double getTotalGuardBandwidth() {
		return totalGuardBw;
	}
	
	
	double getTotalExitBandwidth() {
		return totalExitBw;
	}

	private void adjustTotals(Router router, double bw) {
		if(router.isExit()) {
			totalExitBw += bw;
		} else {
			totalNonExitBw += bw;
		}
		if(router.isPossibleGuard()) {
			totalGuardBw += bw;
		}
	}

	void addRouterUnknown(Router router) {
		final WeightedRouter wr = new WeightedRouter(router, 0);
		wr.isUnknown = true;
		weightedRouters.add(wr);
		unknownCount += 1;
	}
	
	int getRouterCount() {
		return weightedRouters.size();
	}
	
	int getUnknownCount() {
		return unknownCount;
	}
	
	void fixUnknownValues() {
		if(unknownCount == 0) {
			return;
		}
		if(isTotalBandwidthZero()) {
			fixUnknownValues(40000, 20000);
		} else {
			final int knownCount = weightedRouters.size() - unknownCount;
			final long average = (long) (getTotalBandwidth() / knownCount);
			fixUnknownValues(average, average);
		}
	}

	private void fixUnknownValues(long fastBw, long slowBw) {
		for(WeightedRouter wr: weightedRouters) {
			if(wr.isUnknown) {
				long bw = wr.router.isFast() ? fastBw : slowBw;
				wr.weightedBandwidth = bw;
				wr.isUnknown = false;
				adjustTotals(wr.router, bw);
			}
		}
		unknownCount = 0;
		isScaled = false;
	}

	Router chooseRandomRouterByWeight() {
		final long total = getScaledTotal();
		if(total == 0) {
			if(weightedRouters.size() == 0) {
				return null;
			}
			final int idx = random.nextInt(weightedRouters.size());
			return weightedRouters.get(idx).router;
		}
		return chooseFirstElementAboveRandom(random.nextLong(total));
	}
	
	void adjustWeights(double exitWeight, double guardWeight) {
		for(WeightedRouter wr: weightedRouters) {
			Router r = wr.router;
			if(r.isExit() && r.isPossibleGuard()) {
				wr.weightedBandwidth *= (exitWeight * guardWeight);
			} else if(r.isPossibleGuard()) {
				wr.weightedBandwidth *= guardWeight;
			} else if(r.isExit()) {
				wr.weightedBandwidth *= exitWeight;
			}
		}
		scaleRouterWeights();
	}

	private Router chooseFirstElementAboveRandom(long randomValue) {
		long sum = 0;
		Router chosen = null;
		for(WeightedRouter wr: weightedRouters) {
			sum += wr.scaledBandwidth;
			if(sum > randomValue) {
				chosen = wr.router;
				/* Don't return early to avoid leaking timing information about choice */
				randomValue = Long.MAX_VALUE;
			}
		}
		if(chosen == null) {
			return weightedRouters.get(weightedRouters.size() - 1).router;
		}
		return chosen;
	}
	
	private double getWeightedTotal() {
		double total = 0.0;
		for(WeightedRouter wr: weightedRouters) {
			total += wr.weightedBandwidth;
		}
		return total;
	}

	private void scaleRouterWeights() {
		final double scaleFactor = MAX_SCALE / getWeightedTotal();
		for(WeightedRouter wr: weightedRouters) {
			wr.scaleBandwidth(scaleFactor);
		}
		isScaled = true;
	}

	private long getScaledTotal() {
		if(!isScaled) {
			scaleRouterWeights();
		}
		long total = 0;
		for(WeightedRouter wr: weightedRouters) {
			total += wr.scaledBandwidth;
		}
		return total;
	}	
}
   