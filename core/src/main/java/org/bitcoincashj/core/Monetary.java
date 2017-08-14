/*
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoincashj.core;

import java.io.Serializable;

/**
 * Classes implementing this interface represent a monetary value, such as a Bitcoin or fiat amount.
 */
public interface Monetary extends Serializable {

    /**
     * Returns the absolute value of exponent of the value of a "smallest unit" in scientific notation. For Bitcoin, a
     * satoshi is worth 1E-8 so this would be 8.
     */
    int smallestUnitExponent();

    /**
     * Returns the number of "smallest units" of this monetary value. For Bitcoin, this would be the number of satoshis.
     */
    long getValue();

    int signum();
}
