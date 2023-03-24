package org.bitcoinj.wallet;

import org.bitcoinj.base.Sha256Hash;

import java.util.function.Function;

public interface DepthProvider extends Function<Sha256Hash, Integer> {
}
