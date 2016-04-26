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

package org.bitcoinj.wallet;

/**
 * Indicates that the pre-HD random wallet is encrypted, so you should try the upgrade again after getting the
 * users password. This is required because HD wallets are upgraded from random using the private key bytes of
 * the oldest non-rotating key, in order to make the upgrade process itself deterministic.
 */
public class DeterministicUpgradeRequiresPassword extends RuntimeException {}
