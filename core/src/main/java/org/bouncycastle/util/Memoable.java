package org.bouncycastle.util;

public interface Memoable
{
    /**
     * Produce a copy of this object with its configuration and in its current state.
     * <p>
     * The returned object may be used simply to store the state, or may be used as a similar object
     * starting from the copied state.
     */
    public Memoable copy();

    /**
     * Restore a copied object state into this object.
     * <p>
     * Implementations of this method <em>should</em> try to avoid or minimise memory allocation to perform the reset.
     *
     * @param other an object originally {@link #copy() copied} from an object of the same type as this instance.
     * @throws ClassCastException if the provided object is not of the correct type.
     * @throws MemoableResetException if the <b>other</b> parameter is in some other way invalid.
     */
    public void reset(Memoable other);
}
