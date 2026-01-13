package org.bitcoinj.core.internal;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Annotates a program element that exists, or is more widely visible than otherwise necessary, only for use in test code.
 * <p>
 * Replaces Guava's {@code @VisibleForTesting}.
 */
@Documented
@Retention(RetentionPolicy.CLASS)
public @interface VisibleForTesting {
}
