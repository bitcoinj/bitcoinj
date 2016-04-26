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

package org.bitcoinj.jni;

import org.bitcoinj.protocols.channels.PaymentChannelServerListener;
import org.bitcoinj.protocols.channels.ServerConnectionEventHandler;

import javax.annotation.Nullable;
import java.net.SocketAddress;

/**
 * An event listener that relays events to a native C++ object. A pointer to that object is stored in
 * this class using JNI on the native side, thus several instances of this can point to different actual
 * native implementations.
 */
public class NativePaymentChannelHandlerFactory implements PaymentChannelServerListener.HandlerFactory {
    public long ptr;

    @Nullable
    @Override
    public native ServerConnectionEventHandler onNewConnection(SocketAddress clientAddress);
}
