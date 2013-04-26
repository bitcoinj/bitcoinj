package com.google.bitcoin.crypto.hd;

/**
 * @author Matija Mazi <br/>
 *
 * This is just a wrapper for the i (child number) as per BIP 32 with a boolean getter for the first bit and a getter
 * for the actual 0-based child number.
 *
 * This class is immutable.
 */
public class ChildNumber {
    public static final int PRIV_BIT = 0x80000000;

    /** Integer i as per BIP 32 spec, including the MSB denoting derivation type (0 = public, 1 = private) **/
    private final int i;

    public ChildNumber(int childNumber, boolean isPrivate) {
        if (hasPrivateBit(childNumber)) {
            throw new IllegalArgumentException("Most significant bit is reserved and shouldn't be set: " + childNumber);
        }
        i = isPrivate ? (childNumber | PRIV_BIT) : childNumber;
    }

    public ChildNumber(int i) {
        this.i = i;
    }

    public int getI() {
        return i;
    }

    public boolean isPrivateDerivation() {
        return hasPrivateBit(i);
    }

    private static boolean hasPrivateBit(int a) {
        return (a & PRIV_BIT) != 0;
    }

    /**
     * @return the child number without the private/public derivation bit set.
     */
    public int getChildNumber() {
        return i & (~PRIV_BIT);
    }

    public String toString() {
        return String.format("%d%s", getChildNumber(), isPrivateDerivation() ? "'" : "");
    }

    @Override
    public boolean equals(Object o) {
        return this == o || !(o == null || getClass() != o.getClass()) && i == ((ChildNumber) o).i;
    }

    @Override
    public int hashCode() {
        return i;
    }
}
