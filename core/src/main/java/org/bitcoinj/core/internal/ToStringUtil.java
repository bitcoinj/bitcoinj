package org.bitcoinj.core.internal;

import org.jspecify.annotations.Nullable;
import java.util.StringJoiner;

/**
 * A utility to help construct {@code toString} strings, replacing Guava's {@code MoreObjects.ToStringUtil}.
 * <p>
 * This class is internal and not part of the public API.
 */
public class ToStringUtil {
    private final StringJoiner joiner;

    private ToStringUtil(String className) {
        this.joiner = new StringJoiner(", ", className + "{", "}");
    }

    /**
     * Creates a new helper for the given object.
     */
    public static ToStringUtil forObject(Object self) {
        return new ToStringUtil(self.getClass().getSimpleName());
    }

    /**
     * Adds a name/value pair to the formatted output.
     */
    public ToStringUtil add(String name, @Nullable Object value) {
        if (value != null) {
            joiner.add(name + "=" + value);
        }
        return this;
    }

    /**
     * Adds a name/value pair to the formatted output.
     */
    public ToStringUtil add(String name, long value) {
        joiner.add(name + "=" + value);
        return this;
    }

    /**
     * Adds a value to the formatted output (without a name).
     */
    public ToStringUtil addValue(@Nullable Object value) {
        if (value != null) {
            joiner.add(value.toString());
        }
        return this;
    }

    /**
     * Adds a value if the condition is true.
     */
    public ToStringUtil addIf(boolean condition, String value) {
        if (condition) {
            joiner.add(value);
        }
        return this;
    }

    @Override
    public String toString() {
        return joiner.toString();
    }
}