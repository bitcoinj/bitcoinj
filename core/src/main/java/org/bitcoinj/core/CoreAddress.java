package org.bitcoinj.core;

import org.bitcoinj.utils.Network;

import java.util.Arrays;
import java.util.Comparator;
import java.util.Objects;

/**
 * An implementation of {@link Address} that contains a {@link NetworkParameters}
 * This is WIP and should probably either be an interface or eliminated entirely.
 */
public abstract class CoreAddress implements Address, NetworkParametersSupplier {
    // Only for use by implementations
    protected int baseHashCode() {
        return Objects.hash(getParameters(), Arrays.hashCode(getBytes()));
    }

    // Only for use by implementations
    protected boolean baseEquals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CoreAddress other = (CoreAddress) o;
        return this.getParameters().equals(other.getParameters()) && Arrays.equals(this.getBytes(), other.getBytes());
    }

    /**
     * Comparison field order for addresses is:
     * <ol>
     *     <li>{@link NetworkParameters#getId()}</li>
     *     <li>Legacy vs. Segwit</li>
     *     <li>(Legacy only) Version byte</li>
     *     <li>remaining {@code bytes}</li>
     * </ol>
     * <p>
     * Implementations use {@link CoreAddress#PARTIAL_ADDRESS_COMPARATOR} for tests 1 and 2.
     *
     * @param o other {@code Address} object
     * @return comparison result
     */
    @Override
    public abstract int compareTo(Address o);

    @Override
    public Network network() {
        return getParameters().network();
    }
    
    /**
     * Comparator for the first two comparison fields in {@code Address} comparisons, see {@link CoreAddress#compareTo(Address)}.
     * Used by {@link LegacyAddress#compareTo(Address)} and {@link SegwitAddress#compareTo(Address)}.
     */
    public static final Comparator<Address> PARTIAL_ADDRESS_COMPARATOR = Comparator
        .comparing(Address::network)                 // First compare netParams
        .thenComparing(CoreAddress::compareTypes);      // Then compare address type (subclass)

    public static int compareTypes(Address a, Address b) {
        if (a instanceof LegacyAddress && b instanceof SegwitAddress) {
            return -1;  // Legacy addresses (starting with 1 or 3) come before Segwit addresses.
        } else if (a instanceof SegwitAddress && b instanceof LegacyAddress) {
            return 1;
        } else {
            return 0;   // Both are the same type: additional `thenComparing()` lambda(s) for that type must finish the comparison
        }
    }
}
