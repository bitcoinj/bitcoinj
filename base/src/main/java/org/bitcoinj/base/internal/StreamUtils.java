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

package org.bitcoinj.base.internal;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Stream Utilities. Bitcoinj is moving towards functional-style programming, immutable data structures, and
 * unmodifiable lists. Since we are currently limited to Java 8, this class contains utility methods that can simplify
 * code in many places.
 */
public class StreamUtils {
   /**
     * Return a collector that collects a {@link Stream} into an unmodifiable list.
     * <p>
     * Java 10 provides {@code Collectors.toUnmodifiableList()} and Java 16 provides {@code Stream.toList()}.
     * If those are not available, use this utility method.
     */
    public static <T> Collector<T, ?, List<T>> toUnmodifiableList() {
        return Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList);
    }
}
