/*
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
 * Classes handling low level network management using either NIO (async io) or older style blocking sockets (useful for
 * using SOCKS proxies, Tor, SSL etc). The code in this package implements a simple network abstraction a little like
 * what the Netty library provides, but with only what bitcoinj needs.
 */
package org.bitcoinj.net;