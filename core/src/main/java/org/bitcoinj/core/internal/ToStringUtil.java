/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core.internal;

import java.util.StringJoiner;

/**
 * A utility to help construct {@code toString} strings, replacing Guava's {@code MoreObjects.ToStringHelper}.
 * <p>
 * This class is internal and not part of the public API.
 */
public class ToStringUtil {
    private final StringJoiner joiner;

    /**
     * @param instance The object instance to format
     */
    public ToStringUtil(Object instance) {
        this.joiner = new StringJoiner(", ", instance.getClass().getSimpleName() + "{", "}");
    }

    /**
     * Adds a name/value pair to the formatted output.
     * If the value is null, it is ignored (mimicking Guava's omitNullValues).
     *
     * @param name  The name of the property
     * @param value The value of the property
     * @return this instance to support fluent chaining
     */
    public ToStringUtil add(String name, Object value) {
        if (value != null) {
            joiner.add(name + "=" + value);
        }
        return this;
    }

    /**
     * Adds a name/value pair to the formatted output.
     *
     * @param name  The name of the property
     * @param value The value of the property
     * @return this instance to support fluent chaining
     */
    public ToStringUtil add(String name, long value) {
        joiner.add(name + "=" + value);
        return this;
    }

    /**
     * Adds an unnamed value to the formatted output.
     *
     * @param value The value to add
     * @return this instance to support fluent chaining
     */
    public ToStringUtil addValue(Object value) {
        joiner.add(String.valueOf(value));
        return this;
    }

    /**
     * Adds an unnamed value to the formatted output only if the condition is true.
     *
     * @param condition The condition to check
     * @param value     The value to add if condition is true
     * @return this instance to support fluent chaining
     */
    public ToStringUtil addIf(boolean condition, String value) {
        if (condition) {
            joiner.add(value);
        }
        return this;
    }

    /**
     * Adds a name/value pair to the formatted output only if the condition is true.
     *
     * @param condition The condition to check
     * @param name      The name of the property
     * @param value     The value to add if condition is true
     * @return this instance to support fluent chaining
     */
    public ToStringUtil addIf(boolean condition, String name, Object value) {
        if (condition) {
            add(name, value);
        }
        return this;
    }

    @Override
    public String toString() {
        return joiner.toString();
    }
}
