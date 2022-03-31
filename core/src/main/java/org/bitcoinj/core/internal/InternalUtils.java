/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core.internal;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Utilities for internal use only.
 */
public class InternalUtils {

    /**
     * A functional interface for joining {@link String}s or {@code Object}s via {@link Object#toString()} using
     * a pre-configured delimiter.
     * <p>
     * In previous versions of <b>bitcoinj</b> this functionality was provided by Guava's {@code Joiner}.
     */
    @FunctionalInterface
    public interface Joiner {
        /**
         * @param objects A list of objects to join (after calling {@link Object#toString()})
         * The components joined into a single {@code String} separated by the pre-configured delimiter.
         */
        String join(List<?> objects);
    }

    /**
     * A functional interface for splitting {@link String}s using a pre-configured regular expression.
     * <p>
     * In previous versions of <b>bitcoinj</b> this functionality was provided by Guava's {@code Splitter}.
     */
    @FunctionalInterface
    public interface Splitter {
        /**
         * @param string The {@code String} to split
         * @return A list of split {@code String components}
         */
        List<String> splitToList(String string);
    }

    /**
     * Return a lambda for joining {@code String}s or {@code Object}s via {@link Object#toString()}.
     * @param delimiter The delimiter used to join the {@code String} components
     * @return A {@code Joiner} (lambda) instance
     */
    public static Joiner joiner(String delimiter) {
        return list -> list.stream()
                .map(Object::toString)
                .collect(Collectors.joining(delimiter));
    }

    /**
     * Return a lambda for splitting a string into components
     * @param regex regular expression used to split components
     * @return A {@code Splitter} (lambda) instance
     */
    public static Splitter splitter(String regex) {
        return s -> Arrays.asList(s.split(regex));
    }

    /**
     * A {@link Joiner} for joining strings into a single string delimited by a space character.
     */
    public static final Joiner SPACE_JOINER = joiner(" ");

    /**
     * A {@link Splitter} for splitting a string into components by whitespace.
     */
    public static final Splitter WHITESPACE_SPLITTER = splitter("\\s+");

    /**
     * Join strings with ", " skipping nulls
     * @param strings varargs strings
     * @return A joined string
     */
    public static String commaJoin(String... strings) {
        return Arrays.stream(strings).filter(Objects::nonNull).collect(Collectors.joining(", "));
    }
}
