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

module org.bitcoinj.wallettool {
    requires java.logging;

    requires org.jspecify;
    requires org.slf4j;
    requires info.picocli;

    requires org.bitcoinj.core;
    // Since bitcoinj-core doesn't have a module-info and IDEs are generally unaware of the
    // processing done by the jlink plugin, we include transitive dependencies here that would
    // be unnecessary if bitcoinj-core were fully modular.
    requires org.bitcoinj.base;     // Transitive via bitcoinj-core
    requires com.google.protobuf;   // Transitive via bitcoinj-core

    opens org.bitcoinj.wallettool to info.picocli;
}
