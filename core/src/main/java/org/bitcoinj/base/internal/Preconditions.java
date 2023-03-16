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

import java.util.function.Supplier;

public class Preconditions {
    /**
     * Ensures the truth of an expression involving one or more parameters to the calling method.
     * @param expression a boolean expression
     * @throws IllegalArgumentException if {@code expression} is false
     */
    public static void checkArgument(boolean expression) {
        if (!expression)
            throw new IllegalArgumentException();
    }

    /**
     * Ensures the truth of an expression involving one or more parameters to the calling method.
     * @param expression a boolean expression
     * @param messageSupplier supplier of the detail message to be used in the event that a IllegalArgumentException is thrown
     * @throws IllegalArgumentException if {@code expression} is false
     */
    public static void checkArgument(boolean expression, Supplier<String> messageSupplier) {
        if (!expression)
            throw new IllegalArgumentException(messageSupplier.get());
    }

    /**
     * Ensures the truth of an expression involving the state of the calling instance, but not
     * involving any parameters to the calling method.
     * @param expression a boolean expression
     * @throws IllegalStateException if {@code expression} is false
     */
    public static void checkState(boolean expression) {
        if (!expression)
            throw new IllegalStateException();
    }

    /**
     * Ensures the truth of an expression involving the state of the calling instance, but not
     * involving any parameters to the calling method.
     * @param expression a boolean expression
     * @param messageSupplier supplier of the detail message to be used in the event that a IllegalStateException is thrown
     * @throws IllegalStateException if {@code expression} is false
     */
    public static void checkState(boolean expression, Supplier<String> messageSupplier) {
        if (!expression)
            throw new IllegalStateException(messageSupplier.get());
    }
}
