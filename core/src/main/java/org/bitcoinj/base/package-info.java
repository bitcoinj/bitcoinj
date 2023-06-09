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

/**
 * The {@code base} package provides foundational types for <b>bitcoinj</b>. These types must have
 * minimal dependencies. The criteria for allowed dependencies for {@code base} types are:
 * <ul>
 *     <li>No dependencies on other packages of bitcoinj</li>
 *     <li>No API dependencies on external libraries other than the core JDK and {@code slf4j-api}</li>
 * </ul>
 * <p>
 * <b>Temporary exception:</b> In the 0.17 release, we are allowing some dependencies on other packages, e.g. to
 * {@link org.bitcoinj.core.NetworkParameters} or to Guava <i>provided</i> that those references are in <b>deprecated</b> methods.
 * This smooths migration by allowing users to, for example, replace {@code import org.bitcoinj.core.Address} with
 * {@code import org.bitcoinj.base.Address} as first step of conversion and then remove usages of the deprecated methods
 * of {@code Address} in a second step.
 * <p>
 * The base package makes bitcoinj more modular as it breaks circular dependencies between existing packages and provides
 * a "zero-dependency" foundation for the other packages. In a future release {@code base} will be
 * split into a separate JAR/module (tentatively {@code bitcoinj-base}.)
 */
package org.bitcoinj.base;
