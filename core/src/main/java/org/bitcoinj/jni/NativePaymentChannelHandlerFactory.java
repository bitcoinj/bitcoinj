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
