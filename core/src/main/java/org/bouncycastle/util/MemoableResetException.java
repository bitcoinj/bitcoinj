package org.bouncycastle.util;

/**
 * Exception to be thrown on a failure to reset an object implementing Memoable.
 * <p>
 * The exception extends ClassCastException to enable users to have a single handling case,
 * only introducing specific handling of this one if required.
 * </p>
 */
public class MemoableResetException
    extends ClassCastException
{
    /**
     * Basic Constructor.
     *
     * @param msg message to be associated with this exception.
     */
    public MemoableResetException(String msg)
    {
        super(msg);
    }
}
